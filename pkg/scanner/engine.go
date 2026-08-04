package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"


	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/csrf"
	"github.com/xsscan/xsscan/pkg/execverify"
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/verify"
	"go.uber.org/zap"
)

type Config struct {
	Concurrency      int
	RateLimit        int
	RateBurst        int
	RequestTimeout   time.Duration
	MaxPayloads      int
	TestHPP          bool    // Enable HTTP Parameter Pollution testing
	WAFBypass        bool    // Enable WAF bypass via payload mutation
	ConfidenceMin    float64 // Minimum confidence threshold (default 0.60)
	RandomUA         bool    // Randomize User-Agent per request
	AdaptiveRate     bool    // Auto-adjust rate limit on 429 responses
	EnableProbe      bool    // Run context probes before payload scanning
	VerifyExecution  bool    // Browser-based execution verification
	VerifyTimeout    time.Duration // Per-finding verification timeout
	CSRFToken        string  // Manual CSRF token (overrides auto-detection)
	CSRFFieldName    string  // CSRF token field name (auto-detected if empty)
}

type Engine struct {
	config    Config
	client    *http.Client
	analyzer  *analyze.Analyzer
	generator *payload.Generator
	verifier  *verify.Verifier
	throttle  *Throttle
	mutator   *payload.Mutator
	mutatorOnce sync.Once
	logger    *zap.Logger

	payloadsSent  int64
	errors        int64
	probeFiltered int
	wafTracker    *WAFTracker
	csrfExtractor *csrf.Extractor

	// csrfToken/fieldName are accessed concurrently from worker goroutines.
	// atomic.Value avoids data races on the 403-refresh path without
	// adding mutex contention to the per-request hot path.
	csrfToken   atomic.Value // stores string
	csrfFieldName atomic.Value // stores string
}

// NewEngine creates a scan engine. If client is nil, a default client
// with cookie jar is created.
func NewEngine(cfg Config, logger *zap.Logger, client *http.Client) *Engine {
	if client == nil {
		client = httpclient.NewClient(cfg.RequestTimeout, nil)
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	if cfg.ConfidenceMin <= 0 {
		cfg.ConfidenceMin = verify.DefaultConfidenceThreshold
	}
	engine := &Engine{
		config:        cfg,
		client:        client,
		analyzer:      analyze.NewAnalyzer(client),
		generator:     payload.NewGenerator(),
		verifier:      verify.NewVerifier(),
		throttle:      NewThrottle(cfg.RateLimit, cfg.RateBurst, cfg.AdaptiveRate),
		wafTracker:    &WAFTracker{},
		logger:        logger,
		csrfExtractor: csrf.NewExtractor(client),
	}
	if cfg.WAFBypass {
		engine.mutator = payload.NewMutator()
	}
	return engine
}

func (e *Engine) SetCallbackURL(cbURL string) {
	e.generator = payload.NewGeneratorWithCallback(cbURL)
}

func (e *Engine) SetPayloadPreset(preset payload.PayloadPreset) {
	e.generator.SetPreset(preset)
}

// SetWordlist loads custom payloads from a wordlist file into the generator.
func (e *Engine) SetWordlist(path string) error {
	return e.generator.LoadWordlist(path)
}

func (e *Engine) Run(ctx context.Context, target model.Target) (*model.ScanResult, error) {
	startTime := time.Now()
	result := &model.ScanResult{Target: target.URL}

	e.logger.Info("Starting scan", zap.String("target", target.URL))

	analysisResult, err := e.analyzer.Analyze(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	for _, fw := range analysisResult.Frameworks {
		e.logger.Info("Framework detected", zap.String("name", fw.Name), zap.Float64("confidence", fw.Confidence))
	}
	if analysisResult.CSP != nil && analysisResult.CSP.Score.Level != "none" {
		e.logger.Info("CSP analyzed",
			zap.String("level", analysisResult.CSP.Score.Level),
			zap.Int("score", analysisResult.CSP.Score.Value),
			zap.Int("bypasses", len(analysisResult.CSP.Bypasses)),
		)
	}

	e.logger.Info("Analysis complete", zap.Int("injection_points", len(analysisResult.InjectionPoints)))

	// Auto-detect CSRF token if not manually provided.
	// The token is applied to all scan requests so that CSRF-protected
	// applications don't reject payload injection requests mid-scan.
	// Stored in atomic.Value for race-free concurrent access by workers.
	if e.config.CSRFToken == "" {
		if token := e.extractCSRFToken(ctx, target); token != "" {
			e.csrfToken.Store(token)
			e.logger.Info("CSRF token auto-detected for scan",
				zap.String("field", func() string { s, _ := e.csrfFieldName.Load().(string); return s }()),
				zap.String("prefix", maskSecret(token)))
		}
	} else {
		e.csrfToken.Store(e.config.CSRFToken)
		e.logger.Info("Using manually provided CSRF token",
			zap.String("prefix", maskSecret(e.config.CSRFToken)))
	}

	if len(analysisResult.InjectionPoints) == 0 {
		result.Stats = model.ScanStats{StartTime: startTime.UnixMilli(), EndTime: time.Now().UnixMilli()}
		return result, nil
	}

	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}
	host := u.Host
	if host == "" {
		host = "unknown"
	}

	/* Context-probe filtering: before generating payloads, verify each
	injection point's reflection context is actually exploitable. This
	skips points where the marker reflects but real payload chars (< > \")
	would be escaped — the marker->payload assumption gap. */
	if e.config.EnableProbe {
		preFilterCount := len(analysisResult.InjectionPoints)
		filtered := make([]model.InjectionPoint, 0, preFilterCount)
		for _, injection := range analysisResult.InjectionPoints {
			if e.runContextProbe(ctx, injection, host) {
				filtered = append(filtered, injection)
			} else {
				e.logger.Info("Injection point filtered by context probe",
					zap.String("param", injection.Parameter.Name))
			}
		}
		e.probeFiltered = preFilterCount - len(filtered)
		analysisResult.InjectionPoints = filtered
		e.logger.Info("Probe filtering complete",
			zap.Int("remaining", len(filtered)))
	}

	/* Build scan tasks */
	type task struct {
		injection model.InjectionPoint
		payload   payload.Payload
	}

	var tasks []task
	for _, injection := range analysisResult.InjectionPoints {
		payloads := e.generatePayloads(injection, analysisResult.Frameworks)
		if e.config.MaxPayloads > 0 && len(payloads) > e.config.MaxPayloads {
			payloads = payloads[:e.config.MaxPayloads]
		}
		for _, p := range payloads {
			tasks = append(tasks, task{injection, p})
		}
	}

	// Concurrent worker pool
	numWorkers := e.config.Concurrency
	if numWorkers <= 0 {
		numWorkers = 1
	}

	taskCh := make(chan task, numWorkers*2)
	resultCh := make(chan *model.Finding, len(tasks))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					e.logger.Error("worker panic recovered", zap.Any("recover", r))
					atomic.AddInt64(&e.errors, 1)
				}
			}()
			for t := range taskCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				finding, err := e.scanPayload(ctx, t.injection, t.payload, analysisResult.CSP, host)
				if err != nil {
					atomic.AddInt64(&e.errors, 1)
					continue
				}
				if finding != nil {
					resultCh <- finding
				}
				atomic.AddInt64(&e.payloadsSent, 1)
			}
		}()
	}

dispatch:
	for _, t := range tasks {
		select {
		case taskCh <- t:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(taskCh)

	wg.Wait()
	close(resultCh)

	// Semantic dedup: collapse findings with the same attack vector class
	// and context class, keeping the highest-confidence one. This replaces
	// crude prefix-based dedup that lost diverse payload variants.
	var allFindings []model.Finding
	for f := range resultCh {
		allFindings = append(allFindings, *f)
	}
	result.Findings = SemanticDedup(allFindings)

	/* Browser execution verification: if enabled, inject each finding's
	payload into a real browser and check whether JavaScript actually
	executes. This upgrades findings from "structural reflection" to
	"confirmed execution" — the difference between an academic scanner
	and a bounty submission tool.

	Auth state (cookies + headers) from the original scan target is
	passed through so that verification works on authenticated pages.
	Without this, the browser would be redirected to a login page and
	the finding would fail verification — a false negative on the most
	important targets. */
	if e.config.VerifyExecution && len(result.Findings) > 0 {
		e.logger.Info("Starting execution verification",
			zap.Int("findings", len(result.Findings)))
		authState := buildAuthState(target)
		result.Findings = e.verifyFindingsWithAuth(ctx, result.Findings, authState)
	}

	result.Stats = model.ScanStats{
		StartTime:       startTime.UnixMilli(),
		EndTime:         time.Now().UnixMilli(),
		Duration:        time.Since(startTime).Milliseconds(),
		ParametersFound: len(analysisResult.InjectionPoints),
		PayloadsSent:    int(atomic.LoadInt64(&e.payloadsSent)),
		ProbeFiltered:   e.probeFiltered,
		Errors:          int(atomic.LoadInt64(&e.errors)),
		WAF:             e.wafTracker.Result(),
	}

	e.logger.Info("Scan complete",
		zap.Int("findings", len(result.Findings)),
		zap.Int64("payloads_sent", atomic.LoadInt64(&e.payloadsSent)),
	)
	return result, nil
}

// payloadsFromTemplates converts templates to payload entries.
// The type and score parameters override the template defaults.
func payloadsFromTemplates(tmpls []payload.PayloadTemplate, pt payload.PayloadType, score float64) []payload.Payload {
	result := make([]payload.Payload, 0, len(tmpls))
	for _, tmpl := range tmpls {
		result = append(result, payload.Payload{
			Value:    tmpl.Value,
			Context:  tmpl.Context,
			Type:     pt,
			Score:    score,
			Desc:     tmpl.Desc,
			Severity: tmpl.Severity,
		})
	}
	return result
}

func (e *Engine) generatePayloads(injection model.InjectionPoint, frameworks []analyze.FrameworkInfo) []payload.Payload {
	payloads := e.generator.Generate(injection)

	for _, fw := range frameworks {
		payloads = append(payloads, payloadsFromTemplates(
			payload.FrameworkPayloads(strings.ToLower(fw.Name)),
			payload.PayloadTypeReflected, 0.75)...)

		if hasRisk, sinks := fw.RiskInfo(); hasRisk {
			for _, sink := range sinks {
				payloads = append(payloads, payload.Payload{
					Value:    `<img src=x onerror=alert(1)>`,
					Context:  ctx.ContextHTMLBody,
					Type:     payload.PayloadTypeDOM,
					Score:    0.7,
					Desc:     fmt.Sprintf("%s %s DOM XSS", fw.Name, sink),
					Severity: model.High,
				})
			}
		}
	}

	payloads = append(payloads, payloadsFromTemplates(
		payload.PolyglotPayloads(),
		payload.PayloadTypeReflected, 0.8)...)

	if e.config.WAFBypass {
		payloads = append(payloads, payloadsFromTemplates(
			payload.AllWAFBypassPayloads(),
			payload.PayloadTypeReflected, 0.7)...)
	}

	return payloads
}

// buildAuthState extracts authentication state from a scan target for
// passing to the browser verifier. This ensures execution verification
// works on authenticated pages (post-login scans, OAuth, JWT).
func buildAuthState(target model.Target) *execverify.AuthState {
	var cookies []*http.Cookie
	var headers map[string]string

	if len(target.Cookies) > 0 {
		cookies = make([]*http.Cookie, len(target.Cookies))
		for i, c := range target.Cookies {
			cp := *c
			cookies[i] = &cp
		}
	}

	// Carry auth-related headers to the browser
	// authHeaderNames is hoisted to package level to avoid per-call allocation
	for _, name := range authHeaderNames {
		if v, ok := target.Headers[name]; ok && v != "" {
			if headers == nil {
				headers = make(map[string]string)
			}
			headers[name] = v
		}
	}

	if cookies == nil && headers == nil {
		return nil
	}
	return &execverify.AuthState{Cookies: cookies, Headers: headers}
}

// verifyFindingsWithAuth runs browser-based execution verification on each finding.
// Uses a worker pool (default 4 concurrent Chrome tabs) to parallelize
// verification — sequential verification of N findings takes N × timeout,
// concurrent verification takes ~N/workers × timeout.
// Findings that fail verification are downgraded in confidence rather than
// removed — the structural reflection is still valid information.
//
// The authState parameter carries cookies and auth headers from the original
// scan target, allowing the browser verifier to test authenticated pages.
func (e *Engine) verifyFindingsWithAuth(stdctx context.Context, findings []model.Finding, authState *execverify.AuthState) []model.Finding {
	if len(findings) == 0 {
		return findings
	}

	verifyTimeout := e.config.VerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = 15 * time.Second
	}

	var verifier *execverify.Verifier
	var err error
	if authState != nil {
		verifier, err = execverify.NewVerifierWithAuth(stdctx, verifyTimeout, authState)
	} else {
		verifier, err = execverify.NewVerifier(stdctx, verifyTimeout)
	}
	if err != nil {
		e.logger.Warn("Failed to create execution verifier (skipping verification)",
			zap.Error(err))
		return findings
	}
	defer verifier.Close()

	// Single finding: skip worker pool overhead
	if len(findings) == 1 {
		return e.verifyOneFinding(verifier, stdctx, findings)
	}

	// Worker pool: min(4, len(findings)) concurrent Chrome tabs
	numWorkers := 4
	if len(findings) < numWorkers {
		numWorkers = len(findings)
	}

	e.logger.Info("Starting concurrent execution verification",
		zap.Int("findings", len(findings)),
		zap.Int("workers", numWorkers),
		zap.Bool("with_auth", authState != nil))

	type indexedResult struct {
		index   int
		finding model.Finding
	}

	taskCh := make(chan int, numWorkers)
	resultCh := make(chan indexedResult, len(findings))
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for idx := range taskCh {
				f := findings[idx]
				e.logger.Info("Verifying execution",
					zap.Int("worker", workerID),
					zap.String("param", f.Parameter),
					zap.String("payload", text.Truncate(f.Payload, 40)))

				result, err := verifier.VerifyFinding(stdctx, f, model.Target{URL: f.URL})
				if err != nil {
					e.logger.Warn("Verification request failed (keeping finding)",
						zap.Int("worker", workerID),
						zap.String("param", f.Parameter),
						zap.Error(err))
					resultCh <- indexedResult{index: idx, finding: f}
					continue
				}

				e.applyVerificationResult(&f, result)
				resultCh <- indexedResult{index: idx, finding: f}
			}
		}(w)
	}

	// Dispatch all finding indices
	for i := range findings {
		taskCh <- i
	}
	close(taskCh)

	wg.Wait()
	close(resultCh)

	// Reassemble in original order
	verified := make([]model.Finding, len(findings))
	for r := range resultCh {
		verified[r.index] = r.finding
	}

	return verified
}

// verifyOneFinding handles a single finding without worker pool overhead.
func (e *Engine) verifyOneFinding(verifier *execverify.Verifier, stdctx context.Context, findings []model.Finding) []model.Finding {
	f := findings[0]
	e.logger.Info("Verifying execution",
		zap.String("param", f.Parameter),
		zap.String("payload", text.Truncate(f.Payload, 40)))

	result, err := verifier.VerifyFinding(stdctx, f, model.Target{URL: f.URL})
	if err != nil {
		e.logger.Warn("Verification request failed (keeping finding)",
			zap.String("param", f.Parameter),
			zap.Error(err))
		return findings
	}

	e.applyVerificationResult(&f, result)
	return []model.Finding{f}
}

// applyVerificationResult updates a finding based on browser verification result.
// Extracted to shared helper used by both concurrent and single-finding paths.
func (e *Engine) applyVerificationResult(f *model.Finding, result *execverify.ExecutionResult) {
	if result.Executed {
		f.ExecutionVerified = true
		f.ExecutionConfidence = result.Confidence
		f.ScreenshotPath = result.ScreenshotPath
		// Boost confidence for browser-verified findings
		f.Confidence = min(f.Confidence+0.15, 1.0)
		e.logger.Info("Execution VERIFIED in browser",
			zap.String("param", f.Parameter),
			zap.String("dialog", result.DialogType),
			zap.Float64("confidence", result.Confidence))
	} else if result.Confidence > 0 {
		// DOM mutation detected but no dialog
		f.ExecutionConfidence = result.Confidence
		e.logger.Info("DOM mutation detected but no dialog",
			zap.String("param", f.Parameter),
			zap.Strings("mutations", result.DOMMutations))
	} else {
		// No execution detected — downgrade confidence slightly
		f.Confidence *= 0.85
		e.logger.Info("Execution NOT verified",
			zap.String("param", f.Parameter),
			zap.String("load_error", result.LoadError))
	}
}

func (e *Engine) trackWAF(wafResult verify.WAFResult) {
	e.wafTracker.Report(wafResult.Detected, wafResult.Name, false)
}

func (e *Engine) scanPayload(ctx context.Context, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy, host string) (*model.Finding, error) {
	finding, wafResult, err := e.doScanPayload(ctx, injection, p, csp, host)
	if err != nil {
		return nil, err
	}
	e.trackWAF(wafResult)

	// Auto-enable WAF bypass: if a WAF was detected and the user didn't
	// explicitly enable --waf-bypass, lazily initialize the mutator so
	// that subsequent payloads attempt WAF bypass. This catches the
	// common case where the user runs a scan, hits a WAF, and would
	// otherwise need to re-run with --waf-bypass.
	if wafResult.Detected && e.mutator == nil && !e.config.WAFBypass {
		e.mutatorOnce.Do(func() {
			e.mutator = payload.NewMutator()
			e.logger.Info("WAF detected — auto-enabling bypass mutations",
				zap.String("waf", wafResult.Name))
		})
	}

	if finding != nil {
		return finding, nil
	}

	if e.mutator != nil {
		wafName := ""
		if wafResult.Detected {
			wafName = wafResult.Name
		}
		mutations := e.mutator.MutateTargeted(p.Value, p.Context, wafName, 5)
		for _, mut := range mutations {
			mutatedPayload := p
			mutatedPayload.Value = mut.Value
			mutatedPayload.Desc = p.Desc + " (" + string(mut.Type) + ")"

			mutFinding, mutWAF, mutErr := e.doScanPayload(ctx, injection, mutatedPayload, csp, host)
			if mutErr != nil {
				err = mutErr
				continue
			}
			e.trackWAF(mutWAF)
			if mutFinding != nil {
				e.wafTracker.Report(true, "", true)
				mutFinding.Description = findingDescription(injection, mutatedPayload) + " [WAF bypass: " + string(mut.Type) + "]"
				mutFinding.Payload = mut.Value
				return mutFinding, nil
			}
		}
	}

	return nil, nil
}

// maxRetries for transient failures (network errors, 5xx, 429).
const maxRetries = 3

// initialBackoff is the base delay before the first retry.
const initialBackoff = 500 * time.Millisecond

// rawResponseCap limits how much of the raw response we capture for findings.
const rawResponseCap = 4096

// buildRequest constructs an http.Request from a target. Shared by
// doScanPayload and sendProbeRequest to avoid duplicating the construction logic.
func (e *Engine) buildRequest(ctx context.Context, target model.Target) (*http.Request, error) {
	var bodyReader io.Reader
	if target.Body != "" {
		bodyReader = strings.NewReader(target.Body)
	}
	req, err := http.NewRequestWithContext(ctx, target.HTTPMethod(), target.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	request.ApplyHeaders(req, target, e.config.RandomUA)
	e.applyCSRFToken(req)
	return req, nil
}

// sendWithRetry injects a payload, sends the request with retry/CSRF-refresh logic,
// and returns the raw HTTP response body plus any WAF detection result.
// This is the network layer — all retry, backoff, 429, 403-refresh, and 5xx
// handling lives here so the caller can focus on result interpretation.
func (e *Engine) sendWithRetry(ctx context.Context, injection model.InjectionPoint, modifiedTarget model.Target, p payload.Payload, host string) (*http.Response, []byte, verify.WAFResult, error) {
	if err := ssrfguard.IsURLTargetAllowed(modifiedTarget.URL); err != nil {
		return nil, nil, verify.WAFResult{}, fmt.Errorf("ssrf blocked: %w", err)
	}

	var resp *http.Response
	var body []byte
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := initialBackoff << (attempt - 1)
			jitter := time.Duration(rand.Int63n(int64(backoff) / 4))
			sleepTime := backoff - backoff/8 + jitter
			e.logger.Debug("retrying after backoff",
				zap.Int("attempt", attempt),
				zap.Duration("sleep", sleepTime),
			)
			select {
			case <-ctx.Done():
				return nil, nil, verify.WAFResult{}, ctx.Err()
			case <-time.After(sleepTime):
			}
		}

		req, err := e.buildRequest(ctx, modifiedTarget)
		if err != nil {
			return nil, nil, verify.WAFResult{}, err
		}

		if err := e.throttle.Wait(ctx, host); err != nil {
			return nil, nil, verify.WAFResult{}, err
		}

		resp, lastErr = e.client.Do(req)
		if lastErr != nil {
			e.logger.Debug("request failed", zap.Error(lastErr), zap.Int("attempt", attempt))
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, lastErr = io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
		resp.Body.Close()
		if lastErr != nil {
			e.logger.Debug("read response failed", zap.Error(lastErr), zap.Int("attempt", attempt))
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			e.throttle.Report429Host(host)
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				if delay := parseRetryAfter(retryAfter); delay > 0 {
					e.logger.Debug("429 received, waiting Retry-After", zap.Duration("wait", delay))
					select {
					case <-ctx.Done():
						return nil, nil, verify.WAFResult{}, ctx.Err()
					case <-time.After(delay):
					}
				}
			}
			continue
		}

		if resp.StatusCode >= 500 {
			e.logger.Debug("server error, will retry", zap.Int("status", resp.StatusCode), zap.Int("attempt", attempt))
			continue
		}

		// CSRF token refresh: a 403 often indicates an expired/rejected CSRF token.
		// Re-extract the token from the target page and retry with the fresh value.
		// This prevents false negatives when the token becomes stale mid-scan.
		if resp.StatusCode == http.StatusForbidden {
			e.logger.Debug("403 received, attempting CSRF token refresh",
				zap.String("param", injection.Parameter.Name),
				zap.Int("attempt", attempt))
			if token := e.extractCSRFToken(ctx, injection.Target); token != "" {
				e.csrfToken.Store(token)
				e.logger.Info("CSRF token refreshed after 403",
					zap.String("field", func() string { s, _ := e.csrfFieldName.Load().(string); return s }()),
					zap.String("prefix", maskSecret(token)))
				// Retry with fresh token only if we have attempts remaining
				if attempt < maxRetries {
					select {
					case <-ctx.Done():
						return nil, nil, verify.WAFResult{}, ctx.Err()
					case <-time.After(100 * time.Millisecond):
					}
					continue
				}
			}
		}

		break
	}

	if lastErr != nil {
		return nil, nil, verify.WAFResult{}, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
	}
	if resp == nil {
		return nil, nil, verify.WAFResult{}, fmt.Errorf("request failed: no response after %d retries", maxRetries)
	}

	e.throttle.ReportSuccessHost(host)
	return resp, body, verify.WAFResult{}, nil
}

// buildFindingFromResponse analyzes an HTTP response and constructs a Finding
// if the payload is reflected in an exploitable context.
// This is the interpretation layer — WAF detection, confidence scoring,
// and finding construction live here.
func (e *Engine) buildFindingFromResponse(resp *http.Response, body []byte, modifiedTarget model.Target, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy) (*model.Finding, verify.WAFResult) {
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)
	wafResult := verify.DetectWAF(resp, bodyStr)
	vResult := e.verifier.VerifyWithThreshold(bodyStr, bodyLower, p, injection, csp, wafResult, e.config.ConfidenceMin)
	if !vResult.Vulnerable {
		return nil, wafResult
	}

	rawReq := buildRawRequest(modifiedTarget)
	rawResp := captureRawResponse(resp, body)

	return &model.Finding{
		ID:          generateID(),
		Type:        model.ReflectedXSS,
		Severity:    p.Severity,
		Confidence:  vResult.Confidence,
		URL:         modifiedTarget.URL,
		Parameter:   injection.Parameter.Name,
		ParamType:   injection.Parameter.Type,
		Payload:     p.Value,
		Contexts:    contextsToStrings(injection.Contexts),
		Evidence:    vResult.Evidence,
		Description: findingDescription(injection, p),
		Remediation: "Sanitize and encode all user input. Implement CSP headers. Use framework escaping.",
		CWE:         "CWE-79",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://portswigger.net/web-security/cross-site-scripting",
		},
		Timestamp:   time.Now(),
		RawRequest:  rawReq,
		RawResponse: rawResp,
		CSPBypasses: convertCSPBypasses(csp),
	}, wafResult
}

// doScanPayload orchestrates payload injection, network request, and finding construction.
// Thin composition layer: inject → sendWithRetry → buildFindingFromResponse.
func (e *Engine) doScanPayload(ctx context.Context, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy, host string) (*model.Finding, verify.WAFResult, error) {
	modifiedTarget, err := e.injectPayload(injection.Target, injection.Parameter, p.Value)
	if err != nil {
		return nil, verify.WAFResult{}, err
	}

	resp, body, _, err := e.sendWithRetry(ctx, injection, modifiedTarget, p, host)
	if err != nil {
		return nil, verify.WAFResult{}, err
	}

	finding, wafResult := e.buildFindingFromResponse(resp, body, modifiedTarget, injection, p, csp)
	return finding, wafResult, nil
}

// convertCSPBypasses converts analyze.CSPBypass entries to model.CSPBypass
// for inclusion in scan findings.
func convertCSPBypasses(csp *analyze.CSPPolicy) []model.CSPBypass {
	if csp == nil {
		return nil
	}
	result := make([]model.CSPBypass, 0, len(csp.Bypasses))
	for _, b := range csp.Bypasses {
		result = append(result, model.CSPBypass{
			Type:        b.Type,
			Description: b.Description,
			Exploit:     b.Exploit,
		})
	}
	return result
}
func buildRawRequest(target model.Target) string {
	var b strings.Builder

	// Parse URL once for both request line and Host header.
	// HTTP/1.1 origin-form: request-target is path?query, Host header carries authority.
	var reqPath, host string
	if u, err := url.Parse(target.URL); err == nil {
		reqPath = u.Path
		if reqPath == "" {
			reqPath = "/"
		}
		if u.RawQuery != "" {
			reqPath += "?" + u.RawQuery
		}
		host = u.Host
	} else {
		reqPath = target.URL
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", target.HTTPMethod(), reqPath)

	if host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}

	for k, v := range target.Headers {
		// Sanitize header values to prevent CRLF injection in raw request output.
		fmt.Fprintf(&b, "%s: %s\r\n", stripCRLF(k), stripCRLF(v))
	}
	if len(target.Cookies) > 0 {
		cookieParts := make([]string, 0, len(target.Cookies))
		for _, c := range target.Cookies {
			if c != nil {
				cookieParts = append(cookieParts, c.Name+"="+c.Value)
			}
		}
		if len(cookieParts) > 0 {
			fmt.Fprintf(&b, "Cookie: %s\r\n", strings.Join(cookieParts, "; "))
		}
	}
	if target.Body != "" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(target.Body))
		b.WriteString("\r\n")
		b.WriteString(target.Body)
	}
	return b.String()
}
func captureRawResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 ")
	b.WriteString(strconv.Itoa(resp.StatusCode))
	b.WriteByte(' ')
	b.WriteString(resp.Status)
	b.WriteString("\r\n")
	for key, vals := range resp.Header {
		for _, v := range vals {
			b.WriteString(key)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	if len(body) > rawResponseCap {
		b.Write(body[:rawResponseCap])
		b.WriteString("\n... [truncated]")
	} else {
		b.Write(body)
	}
	return b.String()
}

func findingDescription(injection model.InjectionPoint, p payload.Payload) string {
	return fmt.Sprintf("Reflected XSS in %s parameter '%s' (%s)", injection.Parameter.Type, injection.Parameter.Name, p.Context.String())
}

// crlfReplacer strips CR/LF characters in a single pass to prevent
// CRLF injection in raw request output.
var crlfReplacer = strings.NewReplacer("\r", "", "\n", "")

// stripCRLF removes carriage return and line feed characters to prevent
// CRLF injection in raw request output.
func stripCRLF(s string) string {
	return crlfReplacer.Replace(s)
}

// cloneTargetForParam creates a copy of target, deep-copying only the
// fields that injectPayload will mutate for the given parameter type.
// Query and path params only replace the URL string — no map/slice copy needed.
// Cookie injection only mutates the Cookies slice — no header copy needed.
func cloneTargetForParam(t model.Target, paramType model.ParamType) model.Target {
	clone := t
	switch paramType {
	case model.ParamHeader:
		clone.Headers = request.CloneHeaders(t.Headers)
	case model.ParamCookie:
		clone.Cookies = request.CloneCookies(t.Cookies)
	case model.ParamBody:
		// Body is a string (value copy), but Content-Length header may change
		clone.Headers = request.CloneHeaders(t.Headers)
	case model.ParamQuery, model.ParamPath:
		// URL string is replaced entirely — no deep copy needed
	}
	return clone
}

func (e *Engine) injectPayload(target model.Target, param model.Parameter, payloadVal string) (model.Target, error) {
	target = cloneTargetForParam(target, param.Type)
	switch param.Type {
	case model.ParamQuery:
		u, err := url.Parse(target.URL)
		if err != nil {
			return target, err
		}
		values := u.Query()
		if e.config.TestHPP {
			values.Add(param.Name, payloadVal)
		} else {
			values.Set(param.Name, payloadVal)
		}
		u.RawQuery = values.Encode()
		target.URL = u.String()

	case model.ParamBody:
		target.Body = request.InjectBodyValue(target.Body, param.Name, payloadVal, target.Headers)

	case model.ParamHeader:
		target.Headers[param.Name] = payloadVal

	case model.ParamCookie:
		replaced := false
		for i, c := range target.Cookies {
			if c.Name == param.Name {
				target.Cookies[i].Value = payloadVal
				replaced = true
				break
			}
		}
		if !replaced {
			target.Cookies = append(target.Cookies, &http.Cookie{
				Name:  param.Name,
				Value: payloadVal,
			})
		}

	case model.ParamPath:
		// Replace the path segment that matches the original param value
		u, err := url.Parse(target.URL)
		if err != nil {
			return target, err
		}
		segments := strings.Split(u.Path, "/")
		for i, seg := range segments {
			if seg == param.Value {
				segments[i] = payloadVal
				break
			}
		}
		u.Path = strings.Join(segments, "/")
		target.URL = u.String()

	default:
		return target, fmt.Errorf("unsupported parameter type: %s", param.Type)
	}

	return target, nil
}

// extractCSRFToken fetches the target page and attempts to extract a CSRF token
// from form inputs, meta tags, response headers, or cookies. Returns the token
// value, or empty string if none found. The detected field name is stored in
// e.csrfFieldName (atomic) for race-free access by worker goroutines.
func (e *Engine) extractCSRFToken(ctx context.Context, target model.Target) string {
	token, err := e.csrfExtractor.ExtractCSRF(target.URL)
	if err != nil || token == nil {
		return ""
	}
	e.csrfFieldName.Store(token.FieldName)
	return token.Value
}

// applyCSRFToken adds the CSRF token to an outgoing request as a header.
// If no token is configured, this is a no-op. The header name is taken from
// CSRFFieldName (auto-detected or empty), defaulting to the standard
// "X-CSRF-Token" header used by most JavaScript frameworks.
func (e *Engine) applyCSRFToken(req *http.Request) {
	token, _ := e.csrfToken.Load().(string)
	if token == "" {
		return
	}
	headerName, _ := e.csrfFieldName.Load().(string)
	if headerName == "" {
		headerName = "X-CSRF-Token"
	}
	req.Header.Set(headerName, token)
}

// maskSecret returns the first 8 chars of s followed by "**".
// Safe for strings shorter than 8 chars.
func maskSecret(s string) string {
	if len(s) > 8 {
		return s[:8] + "**"
	}
	return s + "**"
}

// parseRetryAfter parses the Retry-After header value.
// Supports both delta-seconds (e.g., "120") and HTTP-date (e.g.,
// "Wed, 21 Oct 2015 07:28:00 GMT") formats per RFC 7231.
// Returns 0 if the value cannot be parsed.
func parseRetryAfter(value string) time.Duration {
	// Try delta-seconds first (most common)
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	// Try HTTP-date format
	if t, err := time.Parse(http.TimeFormat, value); err == nil {
		delay := time.Until(t)
		if delay < 0 {
			delay = 0
		}
		// Cap at 30s to avoid excessive waits
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		return delay
	}
	return 0
}

func contextsToStrings(ctxs []ctx.Context) []string {
	var s []string
	for _, c := range ctxs {
		s = append(s, c.Type.String())
	}
	return s
}

var idCounter int64

// authHeaderNames lists headers that carry auth state to the browser verifier.
var authHeaderNames = []string{"Authorization", "Cookie", "X-CSRF-Token", "X-XSRF-Token"}

func generateID() string {
	count := atomic.AddInt64(&idCounter, 1)
	var b strings.Builder
	b.WriteString("XSS-")
	b.WriteString(strconv.FormatInt(time.Now().UnixNano(), 10))
	b.WriteByte('-')
	b.WriteString(strconv.FormatInt(count, 10))
	return b.String()
}
