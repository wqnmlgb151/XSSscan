package stored

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xsscan/xsscan/pkg/analyze"
	xctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/verify"
)

type triggerObservation struct {
	url     string
	body    string
	headers http.Header
	http    model.HTTPExchange
}

func (s *Scanner) fetchObservation(ctx context.Context, rawURL string, target model.Target) (*triggerObservation, error) {
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, rawURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.ApplyHeaders(req, target, false)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trigger HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	if err != nil {
		return nil, err
	}
	return &triggerObservation{url: rawURL, body: string(body), headers: resp.Header.Clone(), http: httpclient.Captured(resp)}, nil
}

// pollObservations preserves the exact response being assessed and partial errors.
// At most four trigger requests run concurrently per injection.
func (s *Scanner) pollObservations(ctx context.Context, urls []string, target model.Target, needle string) ([]*triggerObservation, error) {
	if needle == "" {
		return nil, fmt.Errorf("empty observation marker")
	}
	var problems []error
	for poll := 0; poll < s.config.MaxPolls; poll++ {
		if poll > 0 {
			timer := time.NewTimer(s.config.PollingInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, errors.Join(append(problems, ctx.Err())...)
			case <-timer.C:
			}
		}
		type outcome struct {
			observation *triggerObservation
			err         error
		}
		jobs := make(chan string, len(urls))
		results := make(chan outcome, len(urls))
		for _, u := range urls {
			jobs <- u
		}
		close(jobs)
		var wg sync.WaitGroup
		for i := 0; i < min(4, len(urls)); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for u := range jobs {
					if ctx.Err() != nil {
						return
					}
					observation, err := s.fetchObservation(ctx, u, target)
					if err != nil {
						err = fmt.Errorf("trigger %s: %w", u, err)
					}
					results <- outcome{observation, err}
				}
			}()
		}
		wg.Wait()
		close(results)
		var found []*triggerObservation
		for item := range results {
			if item.err != nil {
				problems = append(problems, item.err)
			}
			if item.observation != nil && strings.Contains(item.observation.body, needle) {
				found = append(found, item.observation)
			}
		}
		if ctx.Err() != nil {
			problems = append(problems, ctx.Err())
		}
		if len(found) > 0 || ctx.Err() != nil {
			return found, errors.Join(problems...)
		}
	}
	return nil, errors.Join(problems...)
}

func storedPayloads(inj Injection, observations []*triggerObservation) []payload.Payload {
	candidates, _ := storedPayloadsWithDiagnostics(inj, observations)
	return candidates
}

func storedPayloadsWithDiagnostics(inj Injection, observations []*triggerObservation) ([]payload.Payload, []error) {
	var contexts []xctx.Context
	var problems []error
	detector := xctx.NewDetector()
	for _, observation := range observations {
		detected, err := detector.Detect(xctx.Reflection{Content: observation.body, Offset: strings.Index(observation.body, inj.Marker), ParamValue: inj.Marker, StatusCode: http.StatusOK})
		if err == nil {
			for _, c := range detected {
				if c.ParseError != "" {
					problems = append(problems, fmt.Errorf("stored trigger %s: %s", observation.url, c.ParseError))
				}
			}
			contexts = append(contexts, detected...)
		}
	}
	generated := payload.NewGenerator().Generate(model.InjectionPoint{Target: inj.Target, Parameter: inj.Parameter, Contexts: contexts})
	seen := make(map[string]bool)
	counts := make(map[xctx.ContextType]int)
	var selected []payload.Payload
	for _, candidate := range generated {
		if counts[candidate.Context] >= 2 || len(selected) >= 8 || seen[candidate.Value] {
			continue
		}
		if _, _, err := execverify.InstrumentDialogPayload(candidate.Value); err != nil {
			continue
		}
		seen[candidate.Value] = true
		counts[candidate.Context]++
		selected = append(selected, candidate)
	}
	return selected, problems
}

func (s *Scanner) confirmStored(ctx context.Context, inj Injection, urls []string, observations []*triggerObservation) (*model.Finding, error) {
	candidates, problems := storedPayloadsWithDiagnostics(inj, observations)
	var browser *execverify.Verifier
	if s.config.VerifyExecution && len(candidates) > 0 {
		var err error
		browser, err = execverify.NewVerifier(ctx, s.config.VerifyTimeout)
		if err != nil {
			problems = append(problems, err)
		}
		if browser != nil {
			defer browser.Close()
		}
	}
	var best *model.Finding
	verifier := verify.NewVerifier()
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			problems = append(problems, ctx.Err())
			break
		}
		value, message, err := execverify.InstrumentDialogPayload(candidate.Value)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		candidate.Value = value
		submission, err := s.submitExchange(ctx, cloneTargetForParam(inj.Target, inj.Parameter, value))
		if err != nil {
			problems = append(problems, err)
			continue
		}
		responses, err := s.pollObservations(ctx, urls, inj.Target, message)
		if err != nil {
			problems = append(problems, err)
		}
		for _, response := range responses {
			csp := analyze.NewCSPAnalyzer().Parse(request.HeaderMap(response.headers))
			assessment := verifier.VerifyWithThreshold(response.body, strings.ToLower(response.body), candidate, model.InjectionPoint{Target: inj.Target, Parameter: inj.Parameter}, csp, verify.WAFResult{}, verify.DefaultConfidenceThreshold, response.headers.Get("Content-Type"))
			if !assessment.Vulnerable {
				continue
			}
			finding := &model.Finding{ID: generateFindingID(), Type: model.StoredXSS, Severity: candidate.Severity, Confidence: assessment.Confidence, URL: inj.Target.URL, Parameter: inj.Parameter.Name, ParamType: inj.Parameter.Type, Payload: value, Contexts: []string{assessment.Evidence.Context}, Evidence: assessment.Evidence, CWE: "CWE-79", Timestamp: time.Now(), Remediation: "Encode stored data for its output context. Use CSP as defense-in-depth."}
			finding.Evidence.HTTP = &response.http
			finding.Evidence.SubmissionHTTP = &submission
			finding.RawRequest = submission.Request
			finding.RawResponse = response.http.Response
			finding.Evidence.TriggerURL = response.url
			finding.Evidence.DetectionMethod = "stored_context"
			finding.Description = fmt.Sprintf("Stored XSS candidate in parameter '%s': payload reached an executable response context on %s; execution unconfirmed", inj.Parameter.Name, response.url)
			if browser != nil {
				target := inj.Target
				target.URL = response.url
				execution, err := browser.VerifyStoredPage(ctx, target, message)
				if err != nil {
					problems = append(problems, err)
				}
				if err == nil && execution != nil && execution.Executed {
					finding.ExecutionVerified = true
					finding.ExecutionConfidence = execution.Confidence
					finding.Confidence = min(1.0, finding.Confidence+verify.VerificationBoost)
					finding.ScreenshotPath = execution.ScreenshotPath
					finding.Evidence.DetectionMethod = "stored_execution"
					finding.Evidence.Interaction = execution.Interaction
					finding.Evidence.VerificationPayload = value
					finding.Evidence.DialogMessage = execution.DialogMessage
					finding.Description = fmt.Sprintf("Stored XSS in parameter '%s': candidate-specific %s executed on %s", inj.Parameter.Name, execution.DialogType, response.url)
					return finding, errors.Join(problems...)
				}
				finding.Confidence *= 0.85
			}
			if best == nil || finding.Confidence > best.Confidence {
				best = finding
			}
		}
		if best != nil && !s.config.VerifyExecution {
			return best, errors.Join(problems...)
		}
	}
	return best, errors.Join(problems...)
}
