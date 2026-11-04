// Package stored provides stored (persistent) XSS detection.
//
// Unlike reflected XSS where the payload appears immediately in the response,
// stored XSS requires a two-phase lifecycle:
//  1. Injection phase: submit a unique marker to the entry point
//  2. Trigger phase: poll one or more URLs where the stored value may appear
//
// The scanner uses a random marker (xsscan + 12 alphanumeric chars, same format
// as the reflection analyzer) to avoid collisions with existing page content.
// A marker proves persistence only. A separate payload must reach an executable
// response context before this scanner reports a stored XSS candidate.
package stored

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/crawler"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

// Config controls the stored XSS scanner behavior.
type Config struct {
	NoForms bool
	Scope   *crawler.URLScope
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

	// VerifyExecution confirms candidates using a candidate-specific dialog.
	VerifyExecution bool
	VerifyTimeout   time.Duration
}

// Scanner performs stored XSS detection.
type Scanner struct {
	submissions atomic.Int64
	client      *http.Client
	config      Config
	logger      *zap.Logger
}

// discoverTriggerURLs returns the configured trigger URLs, or — when none are
// given — auto-discovers same-host pages via the built-in crawler (BFS from
// the injection target). Covers stored reflections into any publicly
// reachable page (comments on listing pages, profiles, search results)
// without requiring the user to know the display location in advance.
//
// Called once per unique target URL (never per injection): crawler visited
// state is sticky across Crawl calls, so repeated crawls silently degrade to
// zero results. A fresh crawler per call avoids sharing mutable state.
func (s *Scanner) discoverTriggerURLs(ctx context.Context, seedURL string, headers map[string]string) ([]string, error) {
	if len(s.config.TriggerURLs) > 0 {
		return s.config.TriggerURLs, nil
	}
	c := crawler.NewCrawlerWithConfig(s.client, crawler.CrawlerConfig{
		Scope:        s.config.Scope,
		NoForms:      s.config.NoForms,
		MaxDepth:     2,
		MaxPages:     20,
		SameHostOnly: true,
		ExtraHeaders: headers,
	})
	result, err := c.Crawl(ctx, seedURL)
	if err != nil && result == nil {
		return nil, fmt.Errorf("crawl: %w", err)
	}
	for _, issue := range result.Skipped {
		endpoint, _ := url.Parse(issue.Target)
		if endpoint != nil {
			endpoint.User = nil
			endpoint.RawQuery = ""
			endpoint.Fragment = ""
			err = errors.Join(err, fmt.Errorf("stored discovery skipped %s: %s", endpoint.String(), issue.Message))
		}
	}
	if len(result.URLs) == 0 {
		result.URLs = []string{seedURL}
	}
	// Re-fetching a query submission URL with its original values can overwrite
	// the probe before other display pages are polled. Require an independent
	// display URL when query parameters make the seed an injection entry point.
	seed, parseErr := url.Parse(seedURL)
	if parseErr == nil && seed.RawQuery != "" {
		var displayURLs []string
		for _, u := range result.URLs {
			if !automaticTriggerReplaysSeed(seed, u) {
				displayURLs = append(displayURLs, u)
			}
		}
		if len(displayURLs) == 0 {
			return nil, errors.Join(err, fmt.Errorf("no independent stored trigger discovered; configure --trigger-url"))
		}
		result.URLs = displayURLs
	}
	s.logger.Info("auto-discovered trigger URLs via crawler",
		zap.String("seed", seedURL),
		zap.Int("count", len(result.URLs)))
	return result.URLs, err
}

// Automatic discovery cannot assume a query on the submission path is read-only.
// Ignore fragments, query ordering, default ports and trailing-slash aliases.
// Explicit TriggerURLs remain available for a known safe display endpoint.
func automaticTriggerReplaysSeed(seed *url.URL, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || !ssrfguard.SameOrigin(seed.String(), rawURL) {
		return false
	}
	if strings.TrimRight(seed.Path, "/") != strings.TrimRight(u.Path, "/") {
		return false
	}
	query := u.Query()
	for key := range seed.Query() {
		if _, present := query[key]; present {
			return true
		}
	}
	return false
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
	if cfg.VerifyTimeout <= 0 {
		cfg.VerifyTimeout = cfg.RequestTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Scanner{
		client: httpclient.WithRedirectPolicy(httpclient.WithCapture(client)),
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
	findings, err := s.DetectWithError(ctx, injections)
	if err != nil {
		s.logger.Warn("stored detection incomplete", zap.Error(err))
	}
	return findings
}

// DetectWithError retains partial findings and reports failed or canceled checks.
func (s *Scanner) DetectWithError(ctx context.Context, injections []Injection) ([]model.Finding, error) {
	if len(injections) == 0 {
		return nil, nil
	}

	// Resolve trigger URLs ONCE per unique target URL before workers start.
	// Discovery must not run inside workers: crawler visited state is sticky
	// across Crawl calls (repeated crawls return nothing), and lazy crawler
	// creation from concurrent goroutines races.
	var problems []error
	triggerByTarget := make(map[string][]string, len(injections))
	for _, inj := range injections {
		if _, ok := triggerByTarget[inj.Target.URL]; ok {
			continue
		}
		triggerByTarget[inj.Target.URL] = nil
		urls, err := s.discoverTriggerURLs(ctx, inj.Target.URL, inj.Target.Headers)
		if err != nil {
			s.logger.Warn("trigger URL discovery failed",
				zap.String("url", inj.Target.URL), zap.Error(err))
			problems = append(problems, err)
			if len(urls) == 0 {
				continue
			}
		}
		// SSRF-validate every URL that will be fetched (configured AND
		// auto-discovered); their status doesn't change across polls.
		var allowed []string
		for _, u := range urls {
			if err := s.config.Scope.Check(u); err != nil {
				problems = append(problems, fmt.Errorf("stored trigger skipped: %w", err))
				continue
			}
			if err := ssrfguard.IsURLTargetAllowedContext(ctx, u); err != nil {
				s.logger.Warn("trigger URL failed SSRF check", zap.String("url", u), zap.Error(err))
				problems = append(problems, err)
				continue
			}
			allowed = append(allowed, u)
		}
		if len(allowed) == 0 {
			problems = append(problems, fmt.Errorf("no trigger URLs for %s", inj.Target.URL))
		}
		triggerByTarget[inj.Target.URL] = allowed
	}

	concurrency := s.config.Concurrency
	if concurrency > len(injections) {
		concurrency = len(injections)
	}

	injCh := make(chan Injection, concurrency)
	// Requests to one entry point can overwrite each other's stored fields.
	// Keep different entry points concurrent, but serialize one target lifecycle.
	targetLocks := make(map[string]*sync.Mutex, len(triggerByTarget))
	for target := range triggerByTarget {
		targetLocks[target] = &sync.Mutex{}
	}
	resultCh := make(chan *model.Finding, len(injections))
	errCh := make(chan error, len(injections))
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
				if len(triggerByTarget[inj.Target.URL]) == 0 {
					continue
				}
				lock := targetLocks[inj.Target.URL]
				lock.Lock()
				finding, err := s.detectSingleWithError(ctx, inj, triggerByTarget[inj.Target.URL])
				lock.Unlock()
				if err != nil {
					errCh <- fmt.Errorf("%s parameter %s: %w", inj.Target.URL, inj.Parameter.Name, err)
				}
				if finding != nil {
					resultCh <- finding
				}
			}
		}()
	}

dispatch:
	for _, inj := range injections {
		select {
		case injCh <- inj:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(injCh)

	wg.Wait()
	close(resultCh)

	var findings []model.Finding
	for f := range resultCh {
		findings = append(findings, *f)
	}
	close(errCh)
	for err := range errCh {
		problems = append(problems, err)
	}
	if ctx.Err() != nil {
		problems = append(problems, ctx.Err())
	}
	return findings, errors.Join(problems...)
}

// detectSingle performs stored XSS detection for a single injection point.
func (s *Scanner) detectSingle(ctx context.Context, inj Injection, triggerURLs []string) *model.Finding {
	finding, _ := s.detectSingleWithError(ctx, inj, triggerURLs)
	return finding
}

func (s *Scanner) detectSingleWithError(ctx context.Context, inj Injection, triggerURLs []string) (*model.Finding, error) {
	if inj.Marker == "" {
		inj.Marker = analyze.GenerateMarker()
	}
	injectTarget := cloneTargetForParam(inj.Target, inj.Parameter, inj.Marker)

	if err := s.submitMarker(ctx, injectTarget); err != nil {
		s.logger.Debug("marker injection failed",
			zap.String("param", inj.Parameter.Name),
			zap.String("url", inj.Target.URL),
			zap.Error(err),
		)
		return nil, err
	}

	observations, pollErr := s.pollObservations(ctx, triggerURLs, inj.Target, inj.Marker, fmt.Sprintf("stored polling %s:%s", inj.Parameter.Type, inj.Parameter.Name))
	if len(observations) == 0 {
		return nil, pollErr
	}
	finding, confirmationErr := s.confirmStored(ctx, inj, triggerURLs, observations)
	return finding, errors.Join(pollErr, confirmationErr)
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
	case model.ParamPath:
		if injected, err := request.InjectPathValue(t.URL, param.Name, param.Value, marker); err == nil {
			t.URL = injected
		}
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
	_, err := s.submitExchange(ctx, target)
	return err
}

func (s *Scanner) submitExchange(ctx context.Context, target model.Target) (exchange model.HTTPExchange, resultErr error) {
	ctx, capture := httpclient.RecordContext(ctx)
	defer func() { exchange = capture.Snapshot() }()
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, target.URL); err != nil {
		return exchange, fmt.Errorf("ssrf blocked: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()

	var bodyReader io.Reader
	if target.Body != "" {
		bodyReader = strings.NewReader(target.Body)
	}

	req, err := http.NewRequestWithContext(reqCtx, target.HTTPMethod(), target.URL, bodyReader)
	if err != nil {
		return exchange, fmt.Errorf("build request: %w", err)
	}
	request.ApplyHeaders(req, target, false)

	s.submissions.Add(1)
	resp, err := s.client.Do(req)
	if err != nil {
		return exchange, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return exchange, fmt.Errorf("marker submission HTTP %d", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, httpclient.MaxResponseSize)); err != nil {
		return exchange, err
	}

	s.logger.Debug("marker submitted",
		zap.String("url", target.URL),
		zap.Int("status", resp.StatusCode),
	)
	return exchange, nil
}

// pollTriggerURLs checks each trigger URL for the marker, polling up to MaxPolls times.
// Within each poll round, trigger URLs are fetched concurrently.
// triggerURLs are resolved once in Detect — never re-discovered per poll.
func (s *Scanner) pollTriggerURLs(ctx context.Context, urls []string, inj Injection) (bool, string) {
	found, u, _ := s.pollTriggerURLsWithError(ctx, urls, inj)
	return found, u
}

func (s *Scanner) pollTriggerURLsWithError(ctx context.Context, urls []string, inj Injection) (bool, string, error) {
	var problems []error
	for poll := 0; poll < s.config.MaxPolls; poll++ {
		if poll > 0 {
			select {
			case <-ctx.Done():
				return false, "", errors.Join(append(problems, ctx.Err())...)
			case <-time.After(s.config.PollingInterval):
			}
		}
		found, u, err := s.checkTriggerURLsWithError(ctx, urls, inj.Marker, inj.Target.Headers)
		if err != nil {
			problems = append(problems, err)
		}
		if found {
			return true, u, errors.Join(problems...)
		}
	}
	if ctx.Err() != nil {
		problems = append(problems, ctx.Err())
	}
	return false, "", errors.Join(problems...)
}

func (s *Scanner) checkTriggerURLsConcurrent(ctx context.Context, urls []string, marker string, headers map[string]string) (bool, string) {
	found, u, _ := s.checkTriggerURLsWithError(ctx, urls, marker, headers)
	return found, u
}

func (s *Scanner) checkTriggerURLsWithError(ctx context.Context, urls []string, marker string, headers map[string]string) (bool, string, error) {
	type outcome struct {
		url   string
		found bool
		err   error
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
				found, err := s.checkTriggerURL(ctx, u, marker, headers)
				results <- outcome{u, found, err}
			}
		}()
	}
	wg.Wait()
	close(results)
	var evidence string
	var problems []error
	for item := range results {
		if item.err != nil {
			problems = append(problems, fmt.Errorf("trigger %s: %w", item.url, item.err))
		}
		if item.found {
			evidence = item.url
		}
	}
	return evidence != "", evidence, errors.Join(problems...)
}

// checkTriggerURL fetches a trigger URL and searches for the marker in the response body.
func (s *Scanner) checkTriggerURL(ctx context.Context, triggerURL, marker string, headers map[string]string) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, triggerURL, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("trigger HTTP %d", resp.StatusCode)
	}
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

// SubmissionCount includes marker and candidate submission attempts.
func (s *Scanner) SubmissionCount() int { return int(s.submissions.Load()) }
