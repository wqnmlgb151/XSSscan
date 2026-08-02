// Package stored provides stored (persistent) XSS detection.
//
// Unlike reflected XSS where the payload appears immediately in the response,
// stored XSS requires a two-phase lifecycle:
//  1. Injection phase: submit a unique marker to the entry point
//  2. Trigger phase: poll one or more URLs where the stored value may appear
//
// The scanner uses a random marker (xsscan + 12 alphanumeric chars, same format
// as the reflection analyzer) to avoid collisions with existing page content.
// When the marker is found on a trigger URL, we confirm stored XSS with high
// confidence — the marker could only have come from a previous injection.
package stored

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

// Config controls the stored XSS scanner behavior.
type Config struct {
	// TriggerURLs are URLs where stored content may appear (e.g., comment listing,
	// profile page, admin panel). At least one is required.
	TriggerURLs []string

	// PollingInterval is the delay between trigger URL checks.
	// Default: 2 seconds.
	PollingInterval time.Duration

	// MaxPolls is the maximum number of trigger URL checks per injection.
	// Default: 5.
	MaxPolls int

	// RequestTimeout is the timeout for each HTTP request.
	// Default: 30 seconds.
	RequestTimeout time.Duration

	// Concurrency controls parallel injection processing.
	// Default: 1 (sequential). Increase for faster scanning of multiple params.
	Concurrency int
}

// Scanner performs stored XSS detection.
type Scanner struct {
	client *http.Client
	config Config
	logger *zap.Logger
}

// Injection represents a single stored XSS test: inject a marker at the entry
// point, then check trigger URLs for delayed reflection.
type Injection struct {
	Target    model.Target
	Parameter model.Parameter
	Marker    string
}

// NewScanner creates a new stored XSS scanner.
func NewScanner(client *http.Client, cfg Config, logger *zap.Logger) *Scanner {
	if client == nil {
		client = httpclient.NewClient(30*time.Second, nil)
	}
	if cfg.PollingInterval <= 0 {
		cfg.PollingInterval = 2 * time.Second
	}
	if cfg.MaxPolls <= 0 {
		cfg.MaxPolls = 5
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scanner{
		client: client,
		config: cfg,
		logger: logger,
	}
}

// Detect runs the full stored XSS detection pipeline:
//  1. For each injection point, generate a unique marker
//  2. Submit the marker to the entry point
//  3. Poll trigger URLs until the marker appears or max polls reached
//  4. Return findings for confirmed stored XSS
//
// Injections are processed concurrently up to config.Concurrency workers.
func (s *Scanner) Detect(ctx context.Context, injections []Injection) []model.Finding {
	if len(injections) == 0 {
		return nil
	}

	// Pre-validate trigger URLs once (their SSRF status doesn't change across polls).
	for _, u := range s.config.TriggerURLs {
		if err := ssrfguard.IsURLTargetAllowed(u); err != nil {
			s.logger.Warn("trigger URL failed SSRF check", zap.String("url", u), zap.Error(err))
			return nil
		}
	}

	concurrency := s.config.Concurrency
	if concurrency > len(injections) {
		concurrency = len(injections)
	}

	injCh := make(chan Injection, concurrency)
	resultCh := make(chan *model.Finding, len(injections))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for inj := range injCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				finding := s.detectSingle(ctx, inj)
				if finding != nil {
					resultCh <- finding
				}
			}
		}()
	}

	for _, inj := range injections {
		select {
		case injCh <- inj:
		case <-ctx.Done():
			close(injCh)
			wg.Wait()
			return nil
		}
	}
	close(injCh)

	wg.Wait()
	close(resultCh)

	var findings []model.Finding
	for f := range resultCh {
		findings = append(findings, *f)
	}
	return findings
}

// detectSingle performs stored XSS detection for a single injection point.
func (s *Scanner) detectSingle(ctx context.Context, inj Injection) *model.Finding {
	injectTarget := cloneTargetForParam(inj.Target, inj.Parameter, inj.Marker)

	if err := s.submitMarker(ctx, injectTarget); err != nil {
		s.logger.Debug("marker injection failed",
			zap.String("param", inj.Parameter.Name),
			zap.String("url", inj.Target.URL),
			zap.Error(err),
		)
		return nil
	}

	found, evidenceURL := s.pollTriggerURLs(ctx, inj)
	if !found {
		s.logger.Debug("marker not found on trigger URLs",
			zap.String("param", inj.Parameter.Name),
			zap.String("marker", inj.Marker),
		)
		return nil
	}

	return &model.Finding{
		ID:          generateFindingID(),
		Type:        model.StoredXSS,
		Severity:    model.High,
		Confidence:  0.85, // marker could only come from injection
		URL:         inj.Target.URL,
		Parameter:   inj.Parameter.Name,
		ParamType:   inj.Parameter.Type,
		Payload:     inj.Marker,
		Contexts:    []string{"stored"},
		Evidence:    model.Evidence{Reflection: inj.Marker},
		Description: fmt.Sprintf("Stored XSS in %s parameter '%s': marker '%s' appeared on %s after injection", inj.Parameter.Type, inj.Parameter.Name, inj.Marker, evidenceURL),
		Remediation: "Sanitize and encode all user input before storing. Implement output encoding when rendering stored data. Use CSP headers as defense-in-depth.",
		CWE:         "CWE-79",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://portswigger.net/web-security/cross-site-scripting/stored",
		},
		Timestamp: time.Now(),
	}
}

// cloneTargetForParam creates a copy of the target with the marker value injected
// into the specified parameter.
func cloneTargetForParam(t model.Target, param model.Parameter, marker string) model.Target {
	switch param.Type {
	case model.ParamQuery:
		u, err := url.Parse(t.URL)
		if err != nil {
			return t
		}
		q := u.Query()
		q.Set(param.Name, marker)
		u.RawQuery = q.Encode()
		t.URL = u.String()
	case model.ParamBody:
		t.Body = request.InjectBodyValue(t.Body, param.Name, marker, t.Headers)
	case model.ParamHeader:
		clone := make(map[string]string, len(t.Headers))
		for k, v := range t.Headers {
			clone[k] = v
		}
		clone[param.Name] = marker
		t.Headers = clone
	case model.ParamCookie:
		cloned := request.CloneCookies(t.Cookies)
		replaced := false
		for _, c := range cloned {
			if c.Name == param.Name {
				c.Value = marker
				replaced = true
				break
			}
		}
		if !replaced {
			cloned = append(cloned, &http.Cookie{
				Name:  param.Name,
				Value: marker,
			})
		}
		t.Cookies = cloned
	}
	return t
}

// submitMarker sends the marker to the entry point via HTTP request.
func (s *Scanner) submitMarker(ctx context.Context, target model.Target) error {
	if err := ssrfguard.IsURLTargetAllowed(target.URL); err != nil {
		return fmt.Errorf("ssrf blocked: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()

	var bodyReader io.Reader
	if target.Body != "" {
		bodyReader = strings.NewReader(target.Body)
	}

	req, err := http.NewRequestWithContext(reqCtx, target.HTTPMethod(), target.URL, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.ApplyHeaders(req, target, false)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, httpclient.MaxResponseSize))

	s.logger.Debug("marker submitted",
		zap.String("url", target.URL),
		zap.Int("status", resp.StatusCode),
	)
	return nil
}

// pollTriggerURLs checks each trigger URL for the marker, polling up to MaxPolls times.
// Within each poll round, trigger URLs are fetched concurrently.
func (s *Scanner) pollTriggerURLs(ctx context.Context, inj Injection) (bool, string) {
	triggerURLs := s.config.TriggerURLs
	if len(triggerURLs) == 0 {
		triggerURLs = []string{inj.Target.URL}
	}

	for poll := 0; poll < s.config.MaxPolls; poll++ {
		if poll > 0 {
			select {
			case <-ctx.Done():
				return false, ""
			case <-time.After(s.config.PollingInterval):
			}
		}

		if found, url := s.checkTriggerURLsConcurrent(ctx, triggerURLs, inj.Marker); found {
			return true, url
		}
	}
	return false, ""
}

// checkTriggerURLsConcurrent fetches all trigger URLs concurrently within a poll round.
func (s *Scanner) checkTriggerURLsConcurrent(ctx context.Context, triggerURLs []string, marker string) (bool, string) {
	var wg sync.WaitGroup
	resultCh := make(chan string, len(triggerURLs))
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, triggerURL := range triggerURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			found, err := s.checkTriggerURL(cancelCtx, u, marker)
			if err == nil && found {
				select {
				case resultCh <- u:
				default:
				}
			}
		}(triggerURL)
	}

	wg.Wait()
	close(resultCh)

	for u := range resultCh {
		return true, u
	}
	return false, ""
}

// checkTriggerURL fetches a trigger URL and searches for the marker in the response body.
func (s *Scanner) checkTriggerURL(ctx context.Context, triggerURL, marker string) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, triggerURL, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
	if err != nil {
		return false, fmt.Errorf("read body: %w", err)
	}

	return strings.Contains(string(body), marker), nil
}

// generateFindingID produces a unique finding identifier.
func generateFindingID() string {
	return fmt.Sprintf("STORED-%d", time.Now().UnixNano())
}

// ExtractParameters extracts injectable parameters from a target.
// It reuses the analyze package's comprehensive parameter extraction.
// discoverHeaders controls whether dangerous headers are auto-added.
func ExtractParameters(t model.Target) []model.Parameter {
	return analyze.ExtractParameters(t, false)
}
