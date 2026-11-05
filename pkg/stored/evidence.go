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

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	"github.com/wqnmlgb151/XSSscan/pkg/httpclient"
	allocopts "github.com/wqnmlgb151/XSSscan/pkg/internal/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/internal/request"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/pkg/verify"
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
//
// Polling the whole round window rather than stopping at the first round that shows the
// marker is what keeps the outcome independent of trigger-page ordering. Trigger URLs are
// commonly a configuration or edit page next to the page that actually renders stored
// content, and they become ready at different times; returning as soon as one page shows
// the value ends the observation while a slower page is still about to render it. The
// budget is unchanged — a round that shows nothing still runs all MaxPolls rounds — and
// only rounds still lacking evidence are polled, so a page that has already displayed the
// marker is not re-fetched.
func (s *Scanner) pollObservations(ctx context.Context, urls []string, target model.Target, needle, stage string) ([]*triggerObservation, error) {
	if needle == "" {
		return nil, fmt.Errorf("empty observation marker")
	}
	var problems []error
	completed, total := 0, len(urls)*s.config.MaxPolls
	model.ReportProgress(ctx, stage, completed, total)
	// Evidence is accumulated per trigger page and kept across rounds, so a page that
	// displayed the marker early is still reported after a later page displays it too.
	var evidence []*triggerObservation
	shown := make(map[string]bool, len(urls))
	pending := append([]string(nil), urls...)
	for poll := 0; poll < s.config.MaxPolls; poll++ {
		if len(pending) == 0 {
			// Every trigger page has displayed the marker; further rounds would only
			// re-fetch pages that already answered.
			break
		}
		if poll > 0 {
			timer := time.NewTimer(s.config.PollingInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return evidence, errors.Join(append(problems, ctx.Err())...)
			case <-timer.C:
			}
		}
		type outcome struct {
			observation *triggerObservation
			err         error
		}
		jobs := make(chan string, len(pending))
		results := make(chan outcome, len(pending))
		for _, u := range pending {
			jobs <- u
		}
		close(jobs)
		var wg sync.WaitGroup
		for i := 0; i < min(4, len(pending)); i++ {
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
		go func() { wg.Wait(); close(results) }()
		for item := range results {
			completed++
			model.ReportProgress(ctx, stage, completed, total)
			if item.err != nil {
				problems = append(problems, item.err)
			}
			if item.observation != nil && strings.Contains(item.observation.body, needle) && !shown[item.observation.url] {
				shown[item.observation.url] = true
				evidence = append(evidence, item.observation)
			}
		}
		if ctx.Err() != nil {
			problems = append(problems, ctx.Err())
			return evidence, errors.Join(problems...)
		}
		// Only pages that have not yet displayed the marker need another round.
		pending = pending[:0]
		for _, u := range urls {
			if !shown[u] {
				pending = append(pending, u)
			}
		}
	}
	return evidence, errors.Join(problems...)
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
	// Each trigger page is verified in its own right. A page that displays the payload
	// says nothing about whether a different page does: they are separate display sites
	// with separate output contexts, so an execution on one is not a verification of
	// another. The loop therefore does not stop at the first success — it evaluates every
	// page that produced evidence and keeps the strongest result.
	var best *model.Finding
	verifier := verify.NewVerifier()
	for index, candidate := range candidates {
		if ctx.Err() != nil {
			problems = append(problems, ctx.Err())
			break
		}
		value, message, err := execverify.InstrumentDialogPayloadContext(ctx, candidate.Value)
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
		// Every round's observations are considered, not only the round this candidate
		// happened to be confirmed in: a page that started displaying the payload later is
		// still a page that displays it.
		responses, err := s.pollObservations(ctx, urls, inj.Target, message, fmt.Sprintf("stored confirmation %s:%s candidate %d/%d", inj.Parameter.Type, inj.Parameter.Name, index+1, len(candidates)))
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
				finding.Evidence.VerificationPayload = value
				if err != nil {
					finding.Evidence.VerificationError = err.Error()
					problems = append(problems, err)
				}
				if execution != nil {
					finding.Evidence.Diagnostics = append([]string(nil), execution.ConsoleErrors...)
				}
				if (err == nil || allocopts.OnlyCleanupErrors(err)) && execution != nil && execution.Executed {
					finding.ExecutionVerified = true
					finding.ExecutionConfidence = execution.Confidence
					finding.Confidence = min(1.0, finding.Confidence+verify.VerificationBoost)
					finding.ScreenshotPath = execution.ScreenshotPath
					finding.Evidence.DetectionMethod = "stored_execution"
					finding.Evidence.Interaction = execution.Interaction
					finding.Evidence.VerificationPayload = value
					finding.Evidence.DialogMessage = execution.DialogMessage
					finding.Description = fmt.Sprintf("Stored XSS in parameter '%s': candidate-specific %s executed on %s", inj.Parameter.Name, execution.DialogType, response.url)
				} else if err == nil {
					finding.Confidence *= 0.85
				}
			}
			// Keep the strongest result rather than the first one, so a display page that
			// executed is preferred over one that merely rendered.
			if best == nil || betterStoredFinding(finding, best) {
				best = finding
			}
		}
	}
	return best, errors.Join(problems...)
}

// betterStoredFinding reports whether candidate should replace current as the reported
// finding for one injection point.
//
// Execution outweighs everything: a verified execution is a direct observation, while a
// structural match is an inference about the response. Confidence decides only among
// results of the same standing.
func betterStoredFinding(candidate, current *model.Finding) bool {
	if candidate.ExecutionVerified != current.ExecutionVerified {
		return candidate.ExecutionVerified
	}
	return candidate.Confidence > current.Confidence
}
