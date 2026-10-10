package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/browser"
	"github.com/xsscan/xsscan/pkg/dom"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/stored"
)

// DOMModule keeps browser creation and detector lifecycle out of CLI parsing.
func DOMModule(client *http.Client, timeout time.Duration) Module {
	return Module{Type: DOM, Check: func(ctx context.Context, target model.Target) error {
		if err := ssrfguard.IsURLTargetAllowedContext(ctx, target.URL); err != nil {
			return err
		}
		return browser.EnsureChrome()
	}, Run: func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
		result := &model.ScanResult{Target: target.URL}
		auth := &dom.AuthState{}
		if client.Jar != nil {
			if u, err := url.Parse(target.URL); err == nil {
				auth.Cookies = client.Jar.Cookies(u)
			}
		}
		detector, err := dom.NewScannerWithAuth(ctx, timeout, auth)
		if err != nil {
			return result, err
		}
		defer detector.Close()
		var problems []error
		for _, probe := range []string{`<img src=x onerror=alert(1)>`, `<script>alert(1)</script>`, `javascript:alert(1)`, `'-alert(1)-'`, `"><svg onload=alert(1)>`} {
			if ctx.Err() != nil {
				problems = append(problems, ctx.Err())
				break
			}
			result.Stats.PayloadsSent++
			findings, err := detector.DetectDOMXSS(ctx, target, probe)
			result.Findings = append(result.Findings, findings...)
			if err != nil {
				problems = append(problems, err)
			}
		}
		return result, errors.Join(problems...)
	}}
}

func StoredModule(client *http.Client, config stored.Config, discoverHeaders bool) Module {
	return Module{Type: Stored, Check: func(_ context.Context, target model.Target) error {
		if len(analyze.ExtractParameters(target, discoverHeaders)) == 0 {
			return fmt.Errorf("no injectable parameters for stored detection")
		}
		return nil
	}, Run: func(ctx context.Context, target model.Target) (*model.ScanResult, error) {
		result := &model.ScanResult{Target: target.URL}
		params := analyze.ExtractParameters(target, discoverHeaders)
		result.Stats.ParametersFound = len(params)
		injections := make([]stored.Injection, 0, len(params))
		for _, param := range params {
			injections = append(injections, stored.Injection{Target: target, Parameter: param, Marker: analyze.GenerateMarker()})
		}
		detector := stored.NewScanner(client, config, nil)
		findings, err := detector.DetectWithError(ctx, injections)
		result.Findings = findings
		result.Stats.PayloadsSent = detector.SubmissionCount()
		return result, err
	}}
}
