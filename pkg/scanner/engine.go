package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xsscan/xsscan/pkg/analyze"
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/csrf"
	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/httpclient"
	allocopts "github.com/xsscan/xsscan/pkg/internal/chromedp"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/pkg/verify"
	"go.uber.org/zap"
)

type Config struct {
	Concurrency     int
	RateLimit       int
	RateBurst       int
	RequestTimeout  time.Duration
	MaxPayloads     int
	TestHPP         bool          // Enable HTTP Parameter Pollution testing
	WAFBypass       bool          // Enable WAF bypass via payload mutation
	ConfidenceSet   bool          // Preserve an explicitly selected zero threshold
	ConfidenceMin   float64       // Minimum confidence threshold (default 0.60)
	RandomUA        bool          // Randomize User-Agent per request
	AdaptiveRate    bool          // Auto-adjust rate limit on 429 responses
	Strategy        string        // "adaptive" (default) or "exhaustive" candidate scheduling
	EnableProbe     bool          // Run context probes before payload scanning
	VerifyExecution bool          // Browser-based execution verification
	VerifyTimeout   time.Duration // Per-finding verification timeout
	CSRFToken       string        // Manual CSRF token (overrides auto-detection)
	CSRFFieldName   string        // CSRF token field name (auto-detected if empty)
}

// Adaptive is the default; exhaustive remains available for full-range comparison.
const (
	StrategyExhaustive = "exhaustive"
	StrategyAdaptive   = "adaptive"
)

// Empty configuration selects adaptive. Unknown library values retain the
// exhaustive fallback; the CLI rejects unknown values before constructing us.
func (c Config) strategyOrDefault() string {
	if c.Strategy == "" || c.Strategy == StrategyAdaptive {
		return StrategyAdaptive
	}
	return StrategyExhaustive
}

type Engine struct {
	observations observationLog
	wafLogged    int32
	runGate      chan struct{}
	issueMu      sync.Mutex
	runIssues    []model.ScanIssue
	runCoverage  []model.CheckCoverage
	firstError   error
	runTarget    string
	requestsSent int64
	succeeded    int64
	config       Config
	client       *http.Client
	analyzer     *analyze.Analyzer
	generator    *payload.Generator
	verifier     *verify.Verifier
	throttle     *Throttle
	mutator      atomic.Value // stores *payload.Mutator (nil if not initialized)
	logger       *zap.Logger

	payloadsSent  int64
	errors        int64
	probeFiltered int
	// releasesDropped counts scheduler slot releases that arrived after the
	// dispatcher had already returned. It is diagnostic only; a non-zero value
	// on a completed scan means work finished after dispatch stopped.
	releasesDropped int64
	wafTracker      *WAFTracker
	csrfExtractor   *csrf.Extractor

	// csrfToken/fieldName are accessed concurrently from worker goroutines.
	// atomic.Value avoids data races on the 403-refresh path without
	// adding mutex contention to the per-request hot path.
	csrfToken     atomic.Value // stores string
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
	if !cfg.ConfidenceSet && cfg.ConfidenceMin <= 0 {
		cfg.ConfidenceMin = verify.DefaultConfidenceThreshold
	}
	engine := &Engine{
		runGate:    make(chan struct{}, 1),
		config:     cfg,
		client:     client,
		generator:  payload.NewGenerator(),
		verifier:   verify.NewVerifier(),
		throttle:   NewThrottle(cfg.RateLimit, cfg.RateBurst, cfg.AdaptiveRate),
		wafTracker: &WAFTracker{},
		logger:     logger,
	}
	client = httpclient.WithCapture(client)
	baseTransport := client.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	engine.client = &http.Client{Transport: countedTransport{base: baseTransport, count: &engine.requestsSent}, Jar: client.Jar, Timeout: client.Timeout, CheckRedirect: client.CheckRedirect}
	engine.client = httpclient.WithRedirectPolicy(engine.client)
	engine.analyzer = analyze.NewAnalyzer(engine.client)
	engine.csrfExtractor = csrf.NewExtractor(engine.client)
	if cfg.WAFBypass {
		engine.mutator.Store(payload.NewMutator())
	}
	return engine
}

func (e *Engine) SetCallbackURL(cbURL string) {
	e.generator = payload.NewGeneratorWithCallback(cbURL)
}

// SetGenerator replaces the payload generator (DNS callback mode etc.).
func (e *Engine) SetGenerator(g *payload.Generator) {
	e.generator = g
}

func (e *Engine) SetPayloadPreset(preset payload.PayloadPreset) {
	e.generator.SetPreset(preset)
}

// SetWordlist loads custom payloads from a wordlist file into the generator.
func (e *Engine) SetWordlist(path string) error {
	return e.generator.LoadWordlist(path)
}

func (e *Engine) run(ctx context.Context, target model.Target) (*model.ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	startTime := time.Now()
	result := &model.ScanResult{Target: target.URL}

	e.logger.Info("Starting scan", zap.String("target", target.URL))
	model.ReportProgress(ctx, "reflection analysis", 0, 0)

	analysisResult, err := e.analyzer.Analyze(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	for _, analysisErr := range analysisResult.Errors {
		e.recordRunError("analysis", analysisErr)
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
	for _, point := range analysisResult.InjectionPoints {
		for _, c := range point.Contexts {
			if c.ParseError != "" {
				e.recordRunError("javascript-analysis", fmt.Errorf("parameter %s: %s", point.Parameter.Name, c.ParseError))
			}
		}
	}

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
	would be escaped — the marker->payload assumption gap.

	Framework exception: when a framework is detected (Angular/Vue/React),
	the probe is skipped entirely. Probes validate HTML structural chars
	(< > "), but framework template expressions ({{...}}) need none of
	those — a probe failure here would discard injection points whose
	framework payloads are the correct attack vector (e.g., ng-include).
	Execution is still gated by the verifier + confidence threshold. */
	if e.config.EnableProbe && len(analysisResult.Frameworks) == 0 {
		preFilterCount := len(analysisResult.InjectionPoints)
		filtered := make([]model.InjectionPoint, 0, preFilterCount)
		for _, injection := range analysisResult.InjectionPoints {
			kept := e.runContextProbe(ctx, injection, host)
			if kept != nil {
				injection.Contexts = kept
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
	model.ReportProgress(ctx, "context and filter probes", 0, 0)
	type task struct {
		injection model.InjectionPoint
		payload   payload.Payload
		// path is the reflection path this candidate was generated for. It is
		// carried on the task so a worker can release the scheduler's in-flight
		// slot for exactly that path.
		path pathID
	}

	var tasks []task
	// Every task sharing a bucket must have reliable attribution before a proof
	// may stop that bucket. An unmatched fallback must not inherit another task's
	// permission simply because it shares the same scheduling handle.
	convergent := make(map[pathID]bool)
	for _, injection := range analysisResult.InjectionPoints {
		startMarker, endMarker := analyze.GenerateMarker(), analyze.GenerateMarker()
		var profiles analyze.ContextFilters
		if body, err := e.sendProbeRequest(ctx, injection, startMarker+`<>"'()=`+endMarker, host); err == nil {
			profiles = analyze.DetectContextFilters(body, startMarker, endMarker)
		} else {
			e.recordRunError("filter-probe", err)
		}
		payloads := e.generatePayloads(injection, analysisResult.Frameworks)
		generated := len(payloads)
		payloads, emptiedContexts := pruneContextPayloads(payloads, profiles)
		afterPrune := len(payloads)

		/* A context the profile emptied is a coverage fact, not a silent no-op.
		When it happens, widen once: accept payloads written for another context as
		the safety net, since those are the only ones that do not presuppose the
		capability this context has been shown not to have. Every such payload is
		still judged on its own response, so this can only add attempts, not
		conclusions. */
		if len(emptiedContexts) > 0 {
			widened := widenForEmptiedContexts(e.generatePayloads(injection, nil), profiles)
			payloads = append(payloads, widened...)
			e.logger.Info("Filter profile emptied a context; widening once as a safety net",
				zap.String("param", injection.Parameter.Name),
				zap.Strings("emptied_contexts", contextNames(emptiedContexts)),
				zap.Int("safety_net_payloads", len(widened)),
				zap.String("filter_profile", describeFilterProfiles(profiles)))
		}
		payloads = limitPayloads(payloads, e.config.MaxPayloads)

		// Attribute each payload to its reflection path. In the exhaustive
		// strategy this only records identity; the adaptive strategy uses the
		// same attribution to bound how much equivalent work is in flight.
		attributed, attrErr := buildScheduledTasks(injection.Target, injection, payloads)
		if attrErr != nil {
			// Attribution failure must not drop work: fall back to one path for
			// this injection point, without permission to stop early.
			e.recordRunError("scheduling", attrErr)
			_, inputID, positions := reflectionIdentitiesFor(injection.Target, injection)
			id := primaryPathID(inputID, positions)
			attributed = make([]scheduledTask, 0, len(payloads))
			for i := range payloads {
				attributed = append(attributed, scheduledTask{path: id, index: i})
			}
		}
		for i, p := range payloads {
			id := pathID("")
			canConverge := false
			if i < len(attributed) {
				id = attributed[i].path
				canConverge = attributed[i].canConverge
			}
			if previous, seen := convergent[id]; seen {
				canConverge = canConverge && previous
			}
			convergent[id] = canConverge
			tasks = append(tasks, task{injection: injection, payload: p, path: id})
		}
		e.logPayloadBreakdown(injection, payloads, payloadStage{
			generated: generated,
			pruned:    generated - afterPrune,
			limited:   afterPrune - len(payloads),
		}, profiles)
	}

	// Concurrent worker pool
	numWorkers := e.config.Concurrency
	if numWorkers <= 0 {
		numWorkers = 1
	}

	/* Adaptive mode hands work out through the path scheduler; exhaustive mode keeps
	the original prebuilt-slice dispatch untouched. Both feed the same workers, so
	payload identity, scoring and reporting cannot diverge between strategies. */
	strategy := e.config.strategyOrDefault()
	adaptive := strategy == StrategyAdaptive
	resultCh := make(chan *model.Finding, numWorkers*2)
	var allFindings []model.Finding
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for finding := range resultCh {
			allFindings = append(allFindings, *finding)
		}
	}()
	// The worker queue is deliberately shallow. A deep queue lets the dispatcher
	// park unaccounted candidates in it, which defeats the per-path in-flight bound:
	// those parked candidates are not counted as in flight, so a proof arriving while
	// they wait cannot stop them and they are sent anyway. Keeping the queue at one
	// item means the bound the scheduler enforces is the bound that actually holds.
	queueDepth := numWorkers * 2
	if adaptive {
		queueDepth = 1
	}
	taskCh := make(chan dispatchItem[task], queueDepth)
	var wg sync.WaitGroup
	var completed atomic.Int64
	var started, failed, canceled atomic.Int64
	model.ReportProgress(ctx, "reflected payloads", 0, len(tasks))

	// Hold a path's slot through browser verification, so feedback arrives before
	// its next candidate is dispatched. Independent paths retain concurrency.
	provenPaths := newAtomicPathSet()
	var sched *scheduler
	var adaptiveChecks *adaptiveVerification
	if adaptive && e.config.VerifyExecution {
		adaptiveChecks = newAdaptiveVerification(ctx, e, target)
		defer adaptiveChecks.Close()
	}

	// Each dispatchable candidate carries its own completion channel. The worker that
	// runs the attempt closes it, which frees that path's in-flight slot — so a proof
	// arriving while an attempt is queued still stops the path's remaining candidates.
	// It is created for both strategies so the worker path stays identical; only the
	// adaptive dispatcher uses it.
	items := make([]dispatchItem[task], len(tasks))
	for i, t := range tasks {
		items[i] = dispatchItem[task]{item: t, path: t.path, done: make(chan struct{})}
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range taskCh {
				t := entry.item
				select {
				case <-ctx.Done():
					if entry.done != nil {
						close(entry.done)
					}
					return
				default:
				}
				started.Add(1)
				finding, err := func() (finding *model.Finding, err error) {
					defer func() {
						if recovered := recover(); recovered != nil {
							err = fmt.Errorf("payload worker panic: %v", recovered)
						}
					}()
					finding, err = e.scanPayload(ctx, t.injection, t.payload, analysisResult.CSP, host, t.path)
					if err == nil && finding != nil && adaptiveChecks != nil {
						adaptiveChecks.check(ctx, finding)
						if finding.ExecutionVerified && convergent[t.path] {
							provenPaths.add(t.path)
						}
					}
					return finding, err
				}()
				// Free the path's in-flight slot even when the attempt failed: a failed
				// request must not block that path forever.
				if entry.done != nil {
					close(entry.done)
				}
				model.ReportProgress(ctx, "reflected payloads", int(completed.Add(1)), len(tasks))
				if err != nil {
					if ctx.Err() != nil {
						canceled.Add(1)
					} else {
						failed.Add(1)
					}
					e.recordRunError("payload", err)
					continue
				}
				if finding != nil {
					resultCh <- finding
				}
				atomic.AddInt64(&e.succeeded, 1)
			}
		}()
	}

	if adaptive {
		var err error
		sched, err = newSchedulerWithProof(scheduledTasksOf(tasks, func(t task) pathID { return t.path }), 1, provenPaths)
		if err != nil {
			close(taskCh)
			wg.Wait()
			close(resultCh)
			<-collected
			return nil, fmt.Errorf("adaptive scheduling failed: %w", err)
		}
		dispatchIn := make(chan dispatchItem[task], numWorkers*2)
		producerDone := make(chan struct{})
		go func() {
			defer close(producerDone)
			defer close(dispatchIn)
			// Send in slice order: the dispatcher numbers arrivals, so order is what
			// keeps its view of indices aligned with the scheduler's.
			for _, item := range items {
				select {
				case dispatchIn <- item:
				case <-ctx.Done():
					return
				}
			}
		}()
		// Wait for the dispatcher to finish before closing the task channel, so no
		// worker is left receiving from a closed channel it still owns work for.
		<-startPathDispatcher(ctx, dispatchIn, taskCh, sched)
		<-producerDone
	} else {
	dispatch:
		for _, item := range items {
			select {
			case taskCh <- item:
			case <-ctx.Done():
				break dispatch
			}
		}
		close(taskCh)
	}

	wg.Wait()
	close(resultCh)
	<-collected
	e.recordCoverage(model.CheckCoverage{Stage: "reflected_candidates", PlannedKnown: true, Planned: len(tasks), Started: int(started.Load()), Completed: int(started.Load() - failed.Load() - canceled.Load()), Failed: int(failed.Load()), Canceled: int(canceled.Load()), NotStarted: len(tasks) - int(started.Load())})

	// A proof is published before releasing its path's slot. Remaining counts are
	// candidates actually avoided, not a percentage of checks completed.
	if adaptive && sched != nil {
		e.logger.Info("Adaptive scheduling",
			zap.Int("paths", len(sched.stats())),
			zap.Int("candidates", len(tasks)),
			zap.Int("skipped_after_proof", sched.skippedByProof()),
			zap.Int("proven_paths", provenPaths.len()),
			zap.Int64("late_releases", atomic.LoadInt64(&e.releasesDropped)))
	}

	// Semantic dedup: collapse findings with the same attack vector class
	// and context class, keeping the highest-confidence one. This replaces
	// crude prefix-based dedup that lost diverse payload variants.
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
		if adaptiveChecks != nil {
			result.Findings = adaptiveChecks.finish(allFindings)
		} else {
			authState := buildAuthState(target)
			result.Findings = e.verifyGroupedFindings(ctx, allFindings, authState, target)
		}
	}

	// Aggregate same-param same-context findings into single entries with
	// payload variant lists — 9 report lines for one parameter is noise.
	result.Findings = AggregateFindings(result.Findings)

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
// prunePayloads removes payloads that cannot survive the server's filter
// profile. Conservative: when no profile is available (nil), nothing is
// pruned — better to send extra payloads than to miss a finding.
func prunePayloads(payloads []payload.Payload, profile *analyze.FilterProfile) []payload.Payload {
	if profile == nil {
		return payloads
	}
	out := make([]payload.Payload, 0, len(payloads))
	for _, p := range payloads {
		trimmed := strings.TrimSpace(p.Value)
		if strings.ContainsAny(p.Value, "<>") && !profile.AllowsAngleBrackets() {
			continue // < > stripped or encoded → tag payloads are dead
		}
		// Per-quote-type pruning: only drop breakouts using the specific
		// quote character the server encodes.
		if strings.HasPrefix(trimmed, `"`) && !profile.AllowsDoubleQuote() {
			continue
		}
		if strings.HasPrefix(trimmed, `'`) && !profile.AllowsSingleQuote() {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		/* Nothing survived the profile. Returning the whole set here was the old
		behaviour and it was worse than useless: a server that encodes angle brackets
		made every tag payload fail the check, the fallback then restored all of them,
		and the scan spent its entire candidate budget on payloads the profile had
		just established cannot execute in this context.

		The fallback exists so a wrong profile cannot cost a finding, so a safety net
		is kept — but a narrower one. It restores the payloads that do not depend on
		the capability the profile reports as blocked, and only those. The ones that
		do depend on it are precisely what the profile measured, so re-sending them
		re-tests the same hypothesis at full cost. */
		return filterByProfile(payloads, profile)
	}
	return out
}

func payloadsFromTemplates(tmpls []payload.PayloadTemplate, pt payload.PayloadType, score float64) []payload.Payload {
	result := make([]payload.Payload, 0, len(tmpls))
	for _, tmpl := range tmpls {
		result = append(result, payloadFromTemplate(tmpl, pt, score))
	}
	return result
}

// payloadFromTemplate converts a single template without the slice-wrapper
// allocation that payloadsFromTemplates([]T{tmpl}) would incur.
func payloadFromTemplate(tmpl payload.PayloadTemplate, pt payload.PayloadType, score float64) payload.Payload {
	return payload.Payload{
		Value:    tmpl.Value,
		Context:  tmpl.Context,
		Type:     pt,
		Score:    score,
		Desc:     tmpl.Desc,
		Severity: tmpl.Severity,
	}
}

func (e *Engine) generatePayloads(injection model.InjectionPoint, frameworks []analyze.FrameworkInfo) []payload.Payload {
	payloads := e.generator.Generate(injection)

	// Framework/polyglot/WAF payloads claim specific contexts — only send
	// them when the injection point's detected contexts match. A js_string
	// polyglot sent against an html_body reflection is a guaranteed false
	// positive (quotes are inert in body text). Framework payloads are
	// gated the same way: Vue template escapes are inert in body text.
	contextSet := make(map[ctx.ContextType]bool, len(injection.Contexts))
	quoteChars := make(map[ctx.ContextType][]string, len(injection.Contexts))
	for _, c := range injection.Contexts {
		if !c.IsExploitable() {
			continue
		}
		contextSet[c.Type] = true
		quoteChars[c.Type] = append(quoteChars[c.Type], c.QuoteChar)
	}
	if len(injection.Contexts) == 0 {
		contextSet[ctx.ContextHTMLBody] = true // fallback mirrors Generator
		quoteChars[ctx.ContextHTMLBody] = []string{""}
	}

	// quoteOK gates quote-breakout payloads against the detected string
	// quote type (same rule as payload.QuoteCompatible in the Generator).
	quoteOK := func(tmpl payload.PayloadTemplate) bool {
		if !contextSet[tmpl.Context] {
			return false
		}
		for _, quote := range quoteChars[tmpl.Context] {
			if payload.QuoteCompatible(tmpl.Value, tmpl.Context, quote) {
				return true
			}
		}
		return false
	}

	for _, fw := range frameworks {
		for _, tmpl := range payload.FrameworkPayloads(strings.ToLower(fw.Name)) {
			if quoteOK(tmpl) {
				payloads = append(payloads, payloadFromTemplate(tmpl, payload.PayloadTypeReflected, 0.75))
			}
		}

		// Version-aware payload sets: Vue 2 sandbox escapes are dead in Vue 3
		// (sandbox removed); React SSR breakout applies to SSR-rendered apps
		// (Next.js is React-based SSR and gets the same treatment).
		if strings.HasPrefix(fw.Name, "Vue") && strings.HasPrefix(fw.Version, "2") {
			for _, tmpl := range payload.Vue2SandboxPayloads() {
				if quoteOK(tmpl) {
					payloads = append(payloads, payloadFromTemplate(tmpl, payload.PayloadTypeReflected, 0.85))
				}
			}
		}
		if strings.HasPrefix(fw.Name, "React") || fw.Name == "Next.js" {
			for _, tmpl := range payload.ReactSSRPayloads() {
				if quoteOK(tmpl) {
					payloads = append(payloads, payloadFromTemplate(tmpl, payload.PayloadTypeReflected, 0.85))
				}
			}
		}

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

	for _, tmpl := range payload.PolyglotPayloads() {
		if quoteOK(tmpl) {
			payloads = append(payloads, payloadFromTemplate(tmpl, payload.PayloadTypeReflected, 0.8))
		}
	}

	if e.config.WAFBypass {
		for _, tmpl := range payload.AllWAFBypassPayloads() {
			if quoteOK(tmpl) {
				payloads = append(payloads, payloadFromTemplate(tmpl, payload.PayloadTypeReflected, 0.7))
			}
		}
	}

	// Deduplicate by value: identical values produce identical requests. The
	// verifier re-detects the actual context from the response, so the
	// payload's claimed Context metadata adds nothing for dupes — and
	// multi-context injections share several templates across context lists.
	// On collision the higher-scored entry wins (better metadata), except
	// DOM-typed entries which always win: they carry framework-sink
	// descriptions that make findings more actionable on framework targets.
	seen := make(map[string]int, len(payloads))
	out := payloads[:0]
	for _, p := range payloads {
		if idx, ok := seen[p.Value]; ok {
			if p.Type == payload.PayloadTypeDOM && out[idx].Type != payload.PayloadTypeDOM {
				out[idx] = p
			} else if p.Score > out[idx].Score {
				out[idx] = p
			}
			continue
		}
		seen[p.Value] = len(out)
		out = append(out, p)
	}
	return out
}

// buildAuthState extracts authentication state from a scan target for
// passing to the browser verifier. This ensures execution verification
// works on authenticated pages (post-login scans, OAuth, JWT).
func buildAuthState(target model.Target) *execverify.AuthState {
	var cookies []*http.Cookie
	if len(target.Cookies) > 0 {
		cookies = make([]*http.Cookie, len(target.Cookies))
		for i, c := range target.Cookies {
			cp := *c
			cookies[i] = &cp
		}
	}

	if cookies == nil {
		return nil
	}
	return &execverify.AuthState{Cookies: cookies}
}

// verifyFindingsWithAuth retains the internal adapter while using one grouped
// verification path for scans and integration tests.
func (e *Engine) verifyFindingsWithAuth(ctx context.Context, findings []model.Finding, auth *execverify.AuthState, target model.Target) []model.Finding {
	return e.verifyGroupedFindings(ctx, findings, auth, target)
}

// applyVerificationError retains structural evidence without presenting a
// browser transport/policy failure as a completed execution check.
func (e *Engine) applyVerificationError(f *model.Finding, result *execverify.ExecutionResult, err error) {
	if result != nil && result.Executed && allocopts.OnlyCleanupErrors(err) {
		e.applyVerificationResult(f, result)
		f.Evidence.VerificationError = err.Error()
		return
	}
	f.ExecutionVerified = false
	f.ExecutionConfidence = 0
	f.ScreenshotPath = ""
	f.Evidence.DialogMessage = ""
	f.Evidence.VerificationError = err.Error()
	if result != nil {
		f.Evidence.Diagnostics = append([]string(nil), result.ConsoleErrors...)
		f.Evidence.VerificationPayload = result.VerificationPayload
		f.Evidence.Interaction = result.Interaction
	}
}

// applyVerificationResult updates a finding based on browser verification result.
// Extracted to shared helper used by both concurrent and single-finding paths.
func (e *Engine) applyVerificationResult(f *model.Finding, result *execverify.ExecutionResult) {
	f.Evidence.Diagnostics = append([]string(nil), result.ConsoleErrors...)
	f.Evidence.VerificationError = ""
	f.Evidence.VerificationPayload = result.VerificationPayload
	f.Evidence.Interaction = result.Interaction
	if result.Executed {
		f.Evidence.DialogMessage = result.DialogMessage
		f.ExecutionVerified = true
		f.ExecutionConfidence = result.Confidence
		f.ScreenshotPath = result.ScreenshotPath
		// Boost confidence for browser-verified findings
		f.Confidence = min(f.Confidence+verify.VerificationBoost, 1.0)
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
	if !wafResult.Detected {
		return
	}
	e.wafTracker.Report(true, wafResult.Name, false)
	// Log first WAF detection regardless of bypass mode
	if atomic.CompareAndSwapInt32(&e.wafLogged, 0, 1) {
		e.logger.Warn("WAF detected — report will include WAF info",
			zap.String("waf", wafResult.Name),
			zap.String("evidence", wafResult.Evidence))
	}
}

func (e *Engine) scanPayload(ctx context.Context, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy, host string, path pathID) (*model.Finding, error) {
	finding, wafResult, attemptID, err := e.observePayload(ctx, injection, p, csp, host, 0, path)
	if err != nil {
		return nil, err
	}
	e.trackWAF(wafResult)

	// Auto-enable WAF bypass: if a WAF was detected and the user didn't
	// explicitly enable --waf-bypass, lazily initialize the mutator so
	// that subsequent payloads attempt WAF bypass. This catches the
	// common case where the user runs a scan, hits a WAF, and would
	// otherwise need to re-run with --waf-bypass.
	m, _ := e.mutator.Load().(*payload.Mutator)
	if wafResult.Detected && m == nil && !e.config.WAFBypass {
		e.mutator.Store(payload.NewMutator())
		e.logger.Info("WAF detected — auto-enabling bypass mutations",
			zap.String("waf", wafResult.Name))
	}

	if finding != nil {
		return finding, nil
	}

	/* Feedback-gated derivation.

	Mutations are derived only when the attempt actually observed a filter: the
	payload came back altered, truncated, or was refused outright. Absence of a
	reflection is not evidence of filtering — a bypass variant still has to be
	echoed back to be observable — so sending five variants for every
	non-reflecting candidate was pure cost (see derivation.go).

	The decision costs nothing; only acting on it spends requests. When no signal
	justifies a derivation the reason is logged, so a reviewer can tell "no filter
	to bypass" apart from "bypass not attempted". */
	observed, retained := e.observations.recorded(attemptID)
	decision := deriveAllowedFor(observed, retained, wafResult)
	if !decision.mayDerive() {
		e.logger.Debug("Bypass derivation skipped",
			zap.String("param", injection.Parameter.Name),
			zap.String("decision", describeDerivation(decision)))
		return nil, nil
	}

	if mutator, _ := e.mutator.Load().(*payload.Mutator); mutator != nil {
		wafName := ""
		if wafResult.Detected {
			wafName = wafResult.Name
		}
		// Ask for more candidates than the budget so the family filter has something
		// to choose from, then narrow to the justified family within the budget.
		mutations := selectDerivations(
			mutator.MutateTargeted(p.Value, p.Context, wafName, maxDerivationsPerCandidate*3),
			decision, maxDerivationsPerCandidate)
		e.logger.Debug("Deriving bypass candidates",
			zap.String("param", injection.Parameter.Name),
			zap.String("decision", describeDerivation(decision)),
			zap.Int("budget", decision.Budget),
			zap.Int("candidates", len(mutations)))
		for _, mut := range mutations {
			mutatedPayload := p
			mutatedPayload.Value = mut.Value
			mutatedPayload.Desc = p.Desc + " (" + string(mut.Type) + ")"

			mutFinding, mutWAF, _, mutErr := e.observePayload(ctx, injection, mutatedPayload, csp, host, attemptID, path)
			if mutErr != nil {
				e.recordRunError("mutation", mutErr)
				continue
			}
			e.trackWAF(mutWAF)
			if mutFinding != nil {
				if wafResult.Detected {
					e.wafTracker.Report(true, wafName, true)
				} else if e.wafTracker.Detected() {
					e.wafTracker.ReportBypass() // WAF known from an earlier request
				}
				mutFinding.Description = findingDescription(injection, mutatedPayload) + " [WAF bypass: " + string(mut.Type) + "]"
				mutFinding.Payload = mut.Value
				// Encoding mutations (fullwidth, entity, double-encode) only execute
				// if the server normalizes them — the scanner cannot verify that,
				// so discount confidence and mark the uncertainty.
				if payload.IsEncodingMutation(mut.Type) {
					mutFinding.Confidence *= 0.7
					mutFinding.Description += " (requires server-side normalization)"
				}
				return mutFinding, nil
			}
		}
	}

	return nil, nil
}

// maxDerivationsPerCandidate bounds how many bypass candidates one attempt may
// spawn. The previous bound of five came from the mutator call site; it is kept so
// this change alters *when* derivations happen, not how many may happen.
const maxDerivationsPerCandidate = 5

// payloadStage records how the generated candidates were narrowed before dispatch.
// It makes the difference between "the generator is large" and "the budget cap is
// binding" visible, which decides which of the two is worth changing.
type payloadStage struct {
	generated int
	pruned    int
	limited   int
}

// logPayloadBreakdown records where a parameter's candidate budget went.
//
// It exists to answer "what is actually costing requests?" with data rather than
// assumption: the plan's request-reduction target cannot be met by tuning a
// mechanism that turns out to be a small share of the total, so the split between
// generated candidates, what pruning removed, and what the filter probe learned is
// reported before any further optimisation is attempted.
func (e *Engine) logPayloadBreakdown(injection model.InjectionPoint, payloads []payload.Payload, stage payloadStage, profiles analyze.ContextFilters) {
	byType := make(map[payload.PayloadType]int, 4)
	byContext := make(map[ctx.ContextType]int, 8)
	for _, p := range payloads {
		byType[p.Type]++
		byContext[p.Context]++
	}
	e.logger.Debug("Candidate breakdown",
		zap.String("param", injection.Parameter.Name),
		zap.Int("generated", stage.generated),
		zap.Int("pruned_by_filter_profile", stage.pruned),
		zap.Int("dropped_by_max_payloads", stage.limited),
		zap.Int("selected", len(payloads)),
		zap.Int("reflection_contexts", len(injection.Contexts)),
		zap.Any("by_type", byType),
		zap.Int("contexts_in_budget", len(byContext)),
		zap.String("filter_profile", describeFilterProfiles(profiles)))
}

// describeFilterProfiles renders what the per-parameter filter probe established.
// It is a description of observed capability, not a safety verdict: "allows angle
// brackets" means the probe's delimiters survived, nothing more.
func describeFilterProfiles(profiles analyze.ContextFilters) string {
	if len(profiles) == 0 {
		return "none (no profile established; payloads were not pruned by it)"
	}
	parts := make([]string, 0, len(profiles))
	for contextType, profile := range profiles {
		if profile == nil {
			continue
		}
		parts = append(parts, contextType.String()+":"+
			"angle="+yesNo(profile.AllowsAngleBrackets())+
			" dquote="+yesNo(profile.AllowsDoubleQuote())+
			" squote="+yesNo(profile.AllowsSingleQuote()))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

func yesNo(v bool) string {
	if v {
		return "ok"
	}
	return "blocked"
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
	markAttemptPhase(ctx, failurePolicy)
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, modifiedTarget.URL); err != nil {
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

		markAttemptPhase(ctx, failureBuild)
		req, err := e.buildRequest(ctx, modifiedTarget)
		if err != nil {
			return nil, nil, verify.WAFResult{}, err
		}

		markAttemptPhase(ctx, failureWait)
		if err := e.throttle.Wait(ctx, host); err != nil {
			return nil, nil, verify.WAFResult{}, err
		}

		atomic.AddInt64(&e.payloadsSent, 1)
		markAttemptPhase(ctx, failureTransport)
		markPayloadSend(ctx)
		resp, lastErr = e.client.Do(req)
		if lastErr != nil {
			e.logger.Debug("request failed", zap.Error(lastErr), zap.Int("attempt", attempt))
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		markAttemptPhase(ctx, failureRead)
		body, lastErr = io.ReadAll(io.LimitReader(resp.Body, httpclient.MaxResponseSize))
		resp.Body.Close()
		if lastErr != nil {
			e.logger.Debug("read response failed", zap.Error(lastErr), zap.Int("attempt", attempt))
			markAttemptReadError(ctx)
			continue
		}

		markAttemptPhase(ctx, failureStatus)
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

	if resp.StatusCode == 401 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return resp, body, verify.WAFResult{}, fmt.Errorf("HTTP %d after retries", resp.StatusCode)
	}
	if resp.StatusCode == 403 {
		e.recordRunError("request", fmt.Errorf("HTTP 403: request remained forbidden after CSRF refresh"))
	}
	e.throttle.ReportSuccessHost(host)
	return resp, body, verify.WAFResult{}, nil
}

// buildFindingFromResponse analyzes an HTTP response and constructs a Finding
// if the payload is reflected in an exploitable context.
// This is the interpretation layer — WAF detection, confidence scoring,
// and finding construction live here.
func (e *Engine) buildFindingFromResponse(resp *http.Response, body []byte, modifiedTarget model.Target, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy) (*model.Finding, verify.WAFResult) {
	finding, waf, _ := e.assessResponse(resp, body, modifiedTarget, injection, p, csp, "")
	return finding, waf
}

func (e *Engine) assessResponse(resp *http.Response, body []byte, modifiedTarget model.Target, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy, path pathID) (*model.Finding, verify.WAFResult, *verify.VerificationResult) {
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)
	wafResult := verify.DetectWAFWithLower(resp, bodyLower)
	vResult := e.verifier.VerifyWithThreshold(bodyStr, bodyLower, p, injection, csp, wafResult, e.config.ConfidenceMin, resp.Header.Get(request.ContentTypeKey))
	if vResult.Evidence.ParseError != "" {
		e.logger.Debug("Candidate JavaScript parsing failed", zap.String("parameter", injection.Parameter.Name), zap.String("parse_error", vResult.Evidence.ParseError))
		if strings.Contains(vResult.Evidence.ParseError, "analysis limit") {
			e.recordRunError("javascript-analysis", fmt.Errorf("parameter %s: %s", injection.Parameter.Name, vResult.Evidence.ParseError))
		}
	}
	if !vResult.Vulnerable {
		return nil, wafResult, vResult
	}

	exchange := httpclient.Captured(resp)
	rawReq := exchange.Request
	if exchange.InitialRequest != "" {
		rawReq = exchange.InitialRequest
	}
	rawResp := exchange.Response
	if rawReq == "" {
		rawReq = buildRawRequest(modifiedTarget)
		rawResp = captureRawResponse(resp, body)
		exchange = model.HTTPExchange{URL: modifiedTarget.URL, Request: rawReq, Response: rawResp, ResponseTruncated: len(body) > rawResponseCap}
	}
	vResult.Evidence.HTTP = &exchange

	return &model.Finding{
		ID:             generateID(),
		Type:           model.ReflectedXSS,
		Severity:       p.Severity,
		Confidence:     vResult.Confidence,
		URL:            modifiedTarget.URL,
		Parameter:      injection.Parameter.Name,
		ParamType:      injection.Parameter.Type,
		ReflectionPath: string(path),
		Payload:        p.Value,
		Contexts:       contextsToStrings(injection.Contexts),
		Evidence:       vResult.Evidence,
		Description:    findingDescription(injection, p),
		Remediation:    "Sanitize and encode all user input. Implement CSP headers. Use framework escaping.",
		CWE:            "CWE-79",
		References: []string{
			"https://owasp.org/www-community/attacks/xss/",
			"https://portswigger.net/web-security/cross-site-scripting",
		},
		Timestamp:   time.Now(),
		RawRequest:  rawReq,
		RawResponse: rawResp,
		CSPBypasses: convertCSPBypasses(csp),
	}, wafResult, vResult
}

// doScanPayload orchestrates payload injection, network request, and finding construction.
// Thin composition layer: inject → sendWithRetry → buildFindingFromResponse.
func (e *Engine) doScanPayload(ctx context.Context, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy, host string) (*model.Finding, verify.WAFResult, error) {
	finding, waf, _, err := e.observePayload(ctx, injection, p, csp, host, 0, "")
	return finding, waf, err
}

func (e *Engine) observePayload(ctx context.Context, injection model.InjectionPoint, p payload.Payload, csp *analyze.CSPPolicy, host string, parent uint64, path pathID) (finding *model.Finding, waf verify.WAFResult, id uint64, resultErr error) {
	kind := "payload"
	if parent != 0 {
		kind = "mutation"
	}
	o := e.observations.begin(injection, p, parent, kind)
	id = o.ID
	trace, started := &attemptTrace{phase: failureBuild}, time.Now()
	ctx = context.WithValue(ctx, attemptTraceKey{}, trace)
	defer func() {
		finishAttempt(&o, trace, started, resultErr)
		e.observations.record(o)
	}()
	modifiedTarget, err := e.injectPayload(injection.Target, injection.Parameter, p.Value)
	if err != nil {
		return nil, verify.WAFResult{}, id, err
	}

	resp, body, _, err := e.sendWithRetry(ctx, injection, modifiedTarget, p, host)
	captureAttemptResponse(&o, resp, body, p.Value)
	if err != nil {
		return nil, verify.WAFResult{}, id, err
	}

	finding, wafResult, assessment := e.assessResponse(resp, body, modifiedTarget, injection, p, csp, path)
	o.Code, o.Facts, o.ParseError = assessment.Code, assessment.Facts, assessment.Evidence.ParseError
	return finding, wafResult, id, nil
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
		reqPath = u.EscapedPath()
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
		// Preserve credentials for exact report replay.
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
	if target.Body == "" {
		b.WriteString("\r\n")
	}
	return b.String()
}
func captureRawResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 ")
	if resp.Status != "" {
		b.WriteString(resp.Status)
	} else {
		b.WriteString(strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode))
	}
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
			// HPP WAF bypass: prepend a clean value — WAFs inspect the FIRST
			// occurrence while backends (PHP/ASP.NET/JSP) differ on which
			// value wins. ?q=clean&q=<payload> slips the WAF and reaches the app.
			if !values.Has(param.Name) {
				values.Set(param.Name, "test")
			}
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
		injectedURL, err := request.InjectPathValue(target.URL, param.Name, param.Value, payloadVal)
		if err != nil {
			return target, err
		}
		target.URL = injectedURL

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
	token, err := e.csrfExtractor.ExtractCSRFContext(ctx, target.URL)
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

func generateID() string {
	count := atomic.AddInt64(&idCounter, 1)
	var b strings.Builder
	b.WriteString("XSS-")
	b.WriteString(strconv.FormatInt(time.Now().UnixNano(), 10))
	b.WriteByte('-')
	b.WriteString(strconv.FormatInt(count, 10))
	return b.String()
}
