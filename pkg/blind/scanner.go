// Package blind submits callback probes independently of reflected analysis.
package blind

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	"github.com/wqnmlgb151/XSSscan/pkg/callback"
	"github.com/wqnmlgb151/XSSscan/pkg/httpclient"
	"github.com/wqnmlgb151/XSSscan/pkg/internal/request"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

type Config struct {
	Callback        string
	DiscoverHeaders bool
	Observe         func(context.Context) ([]callback.Callback, error)
}

type Scanner struct {
	client *http.Client
	config Config
}

func New(client *http.Client, config Config) *Scanner {
	return &Scanner{client: httpclient.WithRedirectPolicy(httpclient.WithCapture(client)), config: config}
}

func (s *Scanner) Scan(ctx context.Context, target model.Target) (*model.ScanResult, error) {
	result := &model.ScanResult{Target: target.URL}
	if s.config.Callback == "" {
		return result, fmt.Errorf("callback endpoint not configured")
	}
	parameters := analyze.ExtractParameters(target, s.config.DiscoverHeaders)
	result.Stats.ParametersFound = len(parameters)
	if len(parameters) == 0 {
		result.Stats.Status = model.ScanSkipped
		return result, fmt.Errorf("no injectable parameters for blind detection")
	}
	type candidate struct {
		parameter      model.Parameter
		payload, token string
		exchange       model.HTTPExchange
	}
	var candidates []candidate
	var problems []error
	for _, parameter := range parameters {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		for probeIndex := 0; probeIndex < 3; probeIndex++ {
			token := analyze.GenerateMarkerContext(ctx)
			endpoint := strings.TrimSpace(s.config.Callback)
			var generator *payload.Generator
			if !strings.ContainsAny(endpoint, ":/") {
				generator = payload.NewGeneratorWithDNSCallback(token + "." + endpoint)
			} else {
				if !strings.Contains(endpoint, "://") {
					endpoint = "http://" + endpoint
				}
				u, err := url.Parse(endpoint)
				if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
					return result, fmt.Errorf("invalid callback endpoint")
				}
				q := u.Query()
				q.Set("xsscan", token)
				u.RawQuery = q.Encode()
				generator = payload.NewGeneratorWithCallback(u.String())
			}
			blindIndex := 0
			for _, probe := range generator.Generate(model.InjectionPoint{}) {
				if probe.Type != payload.PayloadTypeBlind {
					continue
				}
				blindIndex++
				if blindIndex-1 != probeIndex {
					continue
				}
				modified, err := request.InjectTarget(target, parameter, probe.Value)
				if err == nil {
					err = ssrfguard.IsURLTargetAllowedContext(ctx, modified.URL)
				}
				if err != nil {
					problems = append(problems, err)
					continue
				}
				req, err := http.NewRequestWithContext(ctx, modified.HTTPMethod(), modified.URL, strings.NewReader(modified.Body))
				if err != nil {
					problems = append(problems, err)
					continue
				}
				request.ApplyHeaders(req, modified, false)
				result.Stats.PayloadsSent++
				result.Stats.RequestsSent++
				candidates = append(candidates, candidate{parameter: parameter, payload: probe.Value, token: token})
				recordCtx, capture := httpclient.RecordContext(req.Context())
				req = req.WithContext(recordCtx)
				resp, err := s.client.Do(req)
				if err == nil {
					_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, httpclient.MaxResponseSize))
					resp.Body.Close()
					if resp.StatusCode >= 400 {
						err = fmt.Errorf("blind submission HTTP %d", resp.StatusCode)
					} else {
						err = readErr
					}
				}
				candidates[len(candidates)-1].exchange = capture.Snapshot()
				if err != nil {
					problems = append(problems, err)
				}
			}
		}
	}
	result.Stats.Status = model.ScanCompleted
	if s.config.Observe == nil {
		problems = append(problems, fmt.Errorf("probes submitted; external callback results require collection"))
	} else if len(candidates) > 0 {
		callbacks, err := s.config.Observe(ctx)
		if err != nil {
			problems = append(problems, err)
		}
		seen := make(map[string]bool)
		for _, cb := range callbacks {
			for _, item := range candidates {
				// Correlation is required; callbacks are evidence of a request,
				// not proof that the corresponding XSS executed in a browser.
				if !strings.Contains(cb.Path+"?"+cb.Query, item.token) || seen[item.token] {
					continue
				}
				seen[item.token] = true
				confidence := .85
				if cb.Referer != "" && !ssrfguard.HostsMatch(cb.Referer, target.URL) {
					confidence = .4
				}
				result.Findings = append(result.Findings, model.Finding{ID: "BLIND-" + item.token, Type: model.BlindXSS,
					Severity: model.High, Confidence: confidence, URL: target.URL, Parameter: item.parameter.Name,
					ParamType: item.parameter.Type, Payload: item.payload, Contexts: []string{"blind"},
					Description: "Correlated blind callback candidate; browser execution unverified", Timestamp: time.Now(), RawRequest: item.exchange.Request, RawResponse: item.exchange.Response,
					Evidence: model.Evidence{HTTP: &item.exchange, DetectionMethod: "blind_callback", Reflection: cb.Path + "?" + cb.Query}})
				break
			}
		}
	}
	if len(problems) > 0 {
		result.Stats.Status = model.ScanPartial
		if len(candidates) == 0 {
			result.Stats.Status = model.ScanFailed
		}
	}
	return result, errors.Join(problems...)
}
