// Package dom provides headless browser-based DOM XSS detection.
// Uses Chrome DevTools Protocol (via chromedp) to navigate pages,
// inject JavaScript instrumentation, and detect dangerous sink executions.
package dom

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/xsscan/xsscan/pkg/analyze"
	allocopts "github.com/xsscan/xsscan/pkg/internal/chromedp"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
)

//go:embed hooks.js
var hookScript string

// buildHookScript injects the marker into the CDP sink hook script.
func buildHookScript(marker string) string {
	return strings.Replace(hookScript, "__MARKER_PLACEHOLDER__", marker, 1)
}

// sinkFrame is one stack frame captured when a sink was reached.
//
// A frame is the strongest locating evidence the instrumentation can produce: a static
// script offset identifies a region of a file, whereas a call site identifies the
// expression that actually ran. File and line are reliable when present; a frame whose
// location could not be read is reported with File "unknown" rather than dropped, so a
// missing location is never mistaken for a located one.
type sinkFrame struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// describe renders the frames for a report reader, bounded by the caller.
func describeFrames(frames []sinkFrame) string {
	if len(frames) == 0 {
		return "call site not captured"
	}
	parts := make([]string, 0, len(frames))
	for _, f := range frames {
		if f.File == "unknown" || f.File == "" {
			parts = append(parts, "unknown location")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", f.File, f.Line, f.Column))
	}
	return "called from " + strings.Join(parts, " <- ")
}

// sinkResult is a single recorded sink hit from the hooks.js instrumentation.
//
// Value is a bounded window centred on the marker, not a prefix of what the sink
// received: a prefix loses the marker whenever it sits past the cut, and the bytes
// around the marker are what identify the context it landed in. The position and
// length therefore travel with the snippet so a reader never infers them from it.
type sinkResult struct {
	Sink  string `json:"sink"`
	Value string `json:"value"`
	// ValueLength is the full length of the value the sink received, before the
	// window was taken. Zero means the instrumentation did not report it.
	ValueLength int `json:"value_length"`
	// MarkerAt is the marker's offset within the full value.
	MarkerAt int `json:"marker_at"`
	// WindowStart and WindowEnd bound the captured snippet within the full value.
	WindowStart int `json:"window_start"`
	WindowEnd   int `json:"window_end"`
	// WindowTruncated records that bytes were dropped from either side, so a
	// snippet that looks complete can be told apart from one that is not.
	WindowTruncated bool `json:"window_truncated"`
	// Frames are the call sites captured when the sink was reached, innermost first.
	// Empty means the instrumentation did not capture any (an older hook set, or a
	// stack unavailable in that context) — not that the sink has no caller.
	Frames []sinkFrame `json:"frames"`
}

// hookEvidence is the instrumentation state read back after a page has run.
type hookEvidence struct {
	Installed bool `json:"installed"`
	// Status reports which interception points were actually installed. A hook that
	// failed to install is a blind spot; an empty map means the instrumentation did
	// not report per-hook state at all, which is itself worth knowing.
	Status map[string]bool `json:"status"`
	// Overflowed reports that the record cap was reached, so hits may have been
	// dropped rather than there being none.
	Overflowed bool         `json:"overflowed"`
	Hits       []sinkResult `json:"hits"`
}

// hookCoverage summarises instrumentation completeness for diagnostics and evidence.
type hookCoverage struct {
	Installed      []string
	Failed         []string
	Reported       bool
	Overflowed     bool
	TotalInstalled int
}

// summarise computes the coverage picture from the read-back instrumentation state.
func (e hookEvidence) summarise() hookCoverage {
	coverage := hookCoverage{Reported: e.Status != nil, Overflowed: e.Overflowed}
	for name, ok := range e.Status {
		if ok {
			coverage.Installed = append(coverage.Installed, name)
		} else {
			coverage.Failed = append(coverage.Failed, name)
		}
	}
	sort.Strings(coverage.Installed)
	sort.Strings(coverage.Failed)
	coverage.TotalInstalled = len(coverage.Installed)
	return coverage
}

// describe renders the coverage picture for a report reader. It states what was
// observed, not what is safe: a complete hook set means every interception point
// installed, nothing more, and a blind spot is named rather than omitted.
func (c hookCoverage) describe() string {
	if !c.Reported {
		return "hook installation state not reported by the instrumentation"
	}
	parts := []string{fmt.Sprintf("%d hooks installed", c.TotalInstalled)}
	if len(c.Failed) > 0 {
		parts = append(parts, "failed: "+strings.Join(c.Failed, ","))
	}
	if c.Overflowed {
		parts = append(parts, "record cap reached; hits may have been dropped")
	}
	return strings.Join(parts, "; ")
}

// describeSinkWindow records where the marker sat inside the value the sink received,
// and how complete the captured window is. Instrumentation state is included because a
// hit's meaning depends on whether the hook set was whole.
func describeSinkWindow(hit sinkResult, coverage hookCoverage) string {
	parts := []string{
		fmt.Sprintf("marker at offset %d of %d bytes (window [%d,%d))",
			hit.MarkerAt, hit.ValueLength, hit.WindowStart, hit.WindowEnd),
	}
	if hit.WindowTruncated {
		parts = append(parts, "captured window is partial")
	}
	if site := describeFrames(hit.Frames); site != "" {
		parts = append(parts, site)
	}
	if caveat := sinkInstrumentationCaveat(hit.Sink); caveat != "" {
		parts = append(parts, caveat)
	}
	parts = append(parts, coverage.describe())
	return strings.Join(parts, "; ")
}

// sinkInstrumentationCaveat names the sinks whose evidence the instrumentation itself
// weakens, so a reader does not treat every sink hit as equally strong.
//
// The eval hook cannot preserve direct-eval semantics: `eval(code)` inside a function
// sees that function's lexical scope, but the moment the call is routed through a
// property it becomes an indirect eval in global scope. No JavaScript wrapper can keep
// directness, so a page relying on direct eval behaves differently under
// instrumentation than without it. The hook is kept because a marker that does reach
// eval is still a real signal, but the candidate is labelled rather than presented as
// equivalent to a sink whose wrapper is transparent.
func sinkInstrumentationCaveat(sink string) string {
	switch sink {
	case "eval":
		return "instrumentation caveat: the eval wrapper cannot preserve direct-eval " +
			"semantics, so this hit comes from a page whose eval calls the instrumentation " +
			"already altered"
	case "Function":
		return "instrumentation caveat: the Function wrapper is a passthrough, but a " +
			"wrapper still changes the function's identity"
	}
	return ""
}

// jsStringLiteral safely encodes a string for use as a JS string literal.
// Prevents Self-XSS when user-controlled values are embedded in
// chromedp.Evaluate() scripts.
func jsStringLiteral(s string) string {
	return strconv.Quote(s)
}

// Scanner manages a headless Chrome instance for DOM XSS detection.
type Scanner struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	timeout     time.Duration
	auth        *AuthState
	// replayOriginal makes each DOM test confirm the candidate with the unmarked
	// payload in a fresh browser context. It is the difference between "the marker
	// reached this sink" and "the input itself reached this sink", at the cost of a
	// second page load per test, so it follows the execution-verification setting
	// rather than being unconditional.
	replayOriginal     bool
	browserOnce        sync.Once
	browserCtx         context.Context
	browserCancel      context.CancelFunc
	browserDiagnostics *allocopts.Diagnostics
	browserErr         error
	planMu             sync.RWMutex
	planKey            [sha256.Size]byte
	plan               *documentPlan
}

// SetOriginalReplay enables or disables the independent replay of each DOM candidate
// with its unmarked payload.
//
// It is off by default in the constructor so a caller that wants only the observing
// matrix does not pay for a second page load per test; cmd enables it together with
// execution verification.
func (s *Scanner) SetOriginalReplay(enabled bool) { s.replayOriginal = enabled }

// AuthState carries authentication context for DOM scanning.
// It seeds the browser's cookie jar before navigation so that
// authenticated SPAs and protected endpoints are reachable.
type AuthState struct {
	Cookies []*http.Cookie
}

// NewScanner creates a new headless browser scanner.
func NewScanner(ctx context.Context, timeout time.Duration) (*Scanner, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	allocCtx, allocCancel := allocopts.NewExecAllocator(ctx, allocopts.StandardHeadlessOptions...)

	return &Scanner{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		timeout:     timeout,
	}, nil
}

// NewScannerWithAuth creates a new headless browser scanner with authentication state.
// The auth state is applied to the browser before DOM XSS testing so that
// authenticated pages are reachable.
func NewScannerWithAuth(ctx context.Context, timeout time.Duration, auth *AuthState) (*Scanner, error) {
	s, err := NewScanner(ctx, timeout)
	if err != nil {
		return nil, err
	}
	if auth != nil {
		s.auth = &AuthState{Cookies: request.CloneCookies(auth.Cookies)}
	}
	return s, nil
}

// ApplyAuthState navigates to the target domain and sets cookies via JavaScript evaluation.
// This seeds the browser's cookie jar with session/auth cookies before DOM XSS testing.
func (s *Scanner) ApplyAuthState(ctx context.Context, targetURL string) (resultErr error) {
	if s.auth == nil || len(s.auth.Cookies) == 0 {
		return nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL for auth state: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}

	tabCtx, tabCancel, diagnostics := allocopts.NewTabContext(s.allocCtx)
	defer tabCancel()
	defer func() { resultErr = errors.Join(resultErr, diagnostics.Err()) }()
	withTimeout, cancel := context.WithTimeout(tabCtx, s.timeout)
	defer cancel()

	// Apply the same request scope policy before authenticated navigation.
	guard, policy := allocopts.GuardRequests(targetURL, cancel, nil)
	defer guard.Close()
	if err := chromedp.Run(withTimeout, policy, chromedp.Navigate(targetURL)); err != nil {
		if policyErr := guard.Err(); policyErr != nil {
			return policyErr
		}
		return fmt.Errorf("auth state navigation failed: %w", err)
	}

	for _, cookie := range s.auth.Cookies {
		if cookie == nil {
			continue
		}
		domain := cookie.Domain
		if domain == "" {
			domain = "." + host
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		cookieStr := fmt.Sprintf("%s=%s; domain=%s; path=%s", cookie.Name, cookie.Value, domain, path)
		js := fmt.Sprintf("document.cookie = %q;", cookieStr)
		if err := chromedp.Run(withTimeout, chromedp.Evaluate(js, nil)); err != nil {
			return fmt.Errorf("failed to set cookie %s: %w", cookie.Name, err)
		}
	}
	return nil
}

// Close terminates the browser and releases resources.
func (s *Scanner) Close() error {
	if s.browserCancel != nil {
		s.browserCancel()
	}
	s.allocCancel()
	return nil
}

// domXSSTest represents a single DOM XSS source to test.
type domXSSTest struct {
	Name   string
	Source string // description of the source (fragment, search, etc.)
	NavURL string
	Extra  string // optional JS to execute before navigation (window.name, etc.)
	Flows  []model.JSDataFlow
}

// CheckTarget checks the original request before expanding the source/payload
// matrix. Baseline failure makes all subsequent DOM results incomplete.
func (s *Scanner) CheckTarget(ctx context.Context, target model.Target) error {
	_, err := s.checkTargetPlan(ctx, target)
	if err != nil {
		return fmt.Errorf("DOM baseline navigation: %w", err)
	}
	return nil
}

// DetectDOMXSS tests multiple DOM XSS sources with the given payload.
// It covers: URL fragment, search parameters, document.referrer, window.name.
func (s *Scanner) DetectDOMXSS(ctx context.Context, target model.Target, payload string) ([]model.Finding, error) {
	return s.DetectPayloads(ctx, target, []string{payload})
}

// DetectPayloads runs the full source/payload matrix with bounded concurrency.
// Each check gets a fresh browser context, so cookies and storage never leak
// between candidates even though the browser process is reused.
func (s *Scanner) DetectPayloads(ctx context.Context, target model.Target, payloads []string) ([]model.Finding, error) {
	findings, _, err := s.DetectPayloadsWithCoverage(ctx, target, payloads)
	return findings, err
}

// DetectPayloadsWithCoverage additionally reports the actual source-matrix work.
// Counts exclude baseline navigation and independent replay page loads.
func (s *Scanner) DetectPayloadsWithCoverage(ctx context.Context, target model.Target, payloads []string) ([]model.Finding, model.CheckCoverage, error) {
	coverage := model.CheckCoverage{Stage: "dom_source_checks", Target: target.URL}
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, coverage, fmt.Errorf("invalid target URL: %w", err)
	}
	plan, err := s.targetPlan(ctx, target)
	if err != nil {
		return nil, coverage, fmt.Errorf("DOM baseline navigation: %w", err)
	}

	type task struct {
		test            domXSSTest
		marker, payload string
	}
	var tasks []task
	for _, payload := range payloads {
		marker := analyze.GenerateMarker()
		for _, test := range buildPlannedDOMTests(u, payload, marker, plan) {
			tasks = append(tasks, task{test, marker, payload})
		}
	}
	results := make([][]model.Finding, len(tasks))
	coverage.Planned, coverage.PlannedKnown = len(tasks), true
	started := make([]bool, len(tasks))
	problems := make([]error, len(tasks))
	jobs := make(chan int)
	var workers sync.WaitGroup
	var completed atomic.Int64
	model.ReportProgress(ctx, "DOM source checks", 0, len(tasks))
	for range min(4, len(tasks)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					continue
				}
				started[index] = true
				job := tasks[index]
				results[index], problems[index] = func() (found []model.Finding, err error) {
					defer func() {
						if value := recover(); value != nil {
							found = nil
							err = fmt.Errorf("DOM worker panic: %v", value)
						}
					}()
					return s.runSingleDOMTest(ctx, target, job.test, job.marker, job.payload)
				}()
				if problems[index] != nil {
					problems[index] = fmt.Errorf("DOM source %s: %w", job.test.Name, problems[index])
				}
				model.ReportProgress(ctx, "DOM source checks", int(completed.Add(1)), len(tasks))
			}
		}()
	}
	// Start the checks with an extra observation phase or likely injected
	// executable markup first. Results retain their original matrix order.
	order := make([]int, len(tasks))
	for i := range order {
		order[i] = i
	}
	priority := func(i int) int {
		return plannedSourcePriority(tasks[i].test)
	}
	sort.SliceStable(order, func(i, j int) bool { return priority(order[i]) > priority(order[j]) })
dispatch:
	for _, index := range order {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	var allFindings []model.Finding
	for index, found := range results {
		if !started[index] {
			coverage.NotStarted++
		} else {
			coverage.Started++
			if problems[index] == nil {
				coverage.Completed++
			} else if errors.Is(problems[index], context.Canceled) || errors.Is(problems[index], context.DeadlineExceeded) {
				coverage.Canceled++
			} else {
				coverage.Failed++
			}
		}
		allFindings = append(allFindings, found...)
	}
	return aggregateDOMFindings(allFindings), coverage, errors.Join(append(problems, ctx.Err(), plan.err)...)
}

// buildDOMTests creates test configurations for various DOM XSS sources.
// Covers the OWASP DOM XSS taxonomy: fragment, search, pathname, referrer, window.name,
// javascript: protocol href, localStorage/sessionStorage,
// document.cookie, and postMessage.
func buildDOMTests(u *url.URL, payload string, marker string) []domXSSTest {
	markerPayload := marker + "=" + payload

	tests := []domXSSTest{
		{
			Name:   "fragment",
			Source: "location.hash / location.fragment",
			NavURL: buildURLWithFragment(u, markerPayload),
		},
		{
			Name:   "search",
			Source: "location.search / URLSearchParams",
			NavURL: buildURLWithQuery(u, marker, payload),
		},
		{
			Name:   "pathname",
			Source: "location.pathname (SPA routing)",
			NavURL: buildURLWithPathPrefix(u, marker+"/"+payload),
		},
		{
			Name:   "window.name",
			Source: "window.name (cross-page transport)",
			NavURL: buildURLWithFragment(u, "window-name-test"),
			// Use jsStringLiteral to safely embed payload in JS —
			// prevents single-quote injection if payload contains special chars.
			Extra: fmt.Sprintf("window.name=%s;", jsStringLiteral(markerPayload)),
		},
		{
			Name:   "referrer",
			Source: "document.referrer",
			NavURL: buildURLWithFragment(u, "referrer-test"),
			Extra:  "referrer-spoof",
		},
		{
			Name:   "javascript-href",
			Source: "javascript: protocol in href/src attribute",
			NavURL: buildURLWithJavascriptHref(u, marker, payload),
		},
		{
			Name:   "localStorage",
			Source: "localStorage.getItem (SPA state persistence)",
			NavURL: buildURLWithFragment(u, "localstorage-test"),
			// Store marker+payload into localStorage before page load.
			// SPA apps often read from localStorage and render with innerHTML/v-html.
			Extra: fmt.Sprintf("localStorage.setItem(%s,%s);", jsStringLiteral(marker), jsStringLiteral(markerPayload)),
		},
		{
			Name:   "sessionStorage",
			Source: "sessionStorage.getItem (tab-level state)",
			NavURL: buildURLWithFragment(u, "sessionstorage-test"),
			// Same as localStorage but scoped to a single tab/session.
			Extra: fmt.Sprintf("sessionStorage.setItem(%s,%s);", jsStringLiteral(marker), jsStringLiteral(markerPayload)),
		},
		{
			Name:   "document-cookie",
			Source: "document.cookie (non-HttpOnly cookie)",
			NavURL: buildURLWithFragment(u, "cookie-test"),
			// Set a cookie containing the marker. If the page reads document.cookie
			// and renders it unsanitized, this triggers DOM XSS.
			// The cookie domain is set to the target host so it's readable by JS.
			Extra: fmt.Sprintf("document.cookie=%s;", jsStringLiteral(markerPayload+"; path=/")),
		},
		{
			Name:   "postMessage",
			Source: "window.postMessage (cross-origin messaging)",
			NavURL: buildURLWithFragment(u, "postmessage-test"),
			// postMessage sends data to the page's message event listener.
			// If the page does eval(message.data) or innerHTML = e.data, this triggers.
			// We send after page load so the listener is registered.
			Extra: fmt.Sprintf("post-message-%s", marker),
		},
	}

	for _, key := range sortedQueryKeys(u) {
		tests = append(tests, domXSSTest{Name: "search:" + key, Source: "URLSearchParams parameter " + key, NavURL: buildURLWithQuery(u, key, markerPayload)})
	}
	return tests
}

func buildURLWithFragment(u *url.URL, fragment string) string {
	clone := *u
	clone.Fragment = fragment
	return clone.String()
}

func buildURLWithQuery(u *url.URL, key, value string) string {
	clone := *u
	q := clone.Query()
	q.Set(key, value)
	clone.RawQuery = q.Encode()
	return clone.String()
}

// buildURLWithPathPrefix appends a path segment for pathname-based DOM XSS testing.
func buildURLWithPathPrefix(u *url.URL, prefix string) string {
	clone := *u
	clone.Path = strings.TrimRight(clone.Path, "/") + "/" + prefix
	return clone.String()
}

// buildURLWithJavascriptHref creates a URL that tests javascript: protocol injection.
// The payload is set as a query parameter that the page might use in href attribute.
func buildURLWithJavascriptHref(u *url.URL, marker, payload string) string {
	clone := *u
	q := clone.Query()
	// Test both as a link parameter and as a redirect parameter
	q.Set(marker, "javascript:"+payload)
	clone.RawQuery = q.Encode()
	return clone.String()
}

// runSingleDOMTest navigates to a URL and checks if the payload reaches a DOM sink.
func (s *Scanner) runSingleDOMTest(ctx context.Context, target model.Target, test domXSSTest, marker, payload string, plans ...*documentPlan) (result []model.Finding, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.browserOnce.Do(func() {
		s.browserCtx, s.browserCancel, s.browserDiagnostics = allocopts.NewTabContext(s.allocCtx)
		// The first Run owns the browser lifetime. Canceling a temporary startup
		// context on success would also terminate the shared browser.
		timer := time.AfterFunc(s.timeout, s.browserCancel)
		defer timer.Stop()
		stop := context.AfterFunc(ctx, s.browserCancel)
		defer stop()
		s.browserErr = chromedp.Run(s.browserCtx)
	})
	if s.browserErr != nil {
		return nil, s.browserErr
	}
	tabCtx, tabCancel, diagnostics, err := allocopts.NewIsolatedTabContext(ctx, s.browserCtx, s.timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		tabCancel()
		if err := diagnostics.Err(); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, err)
		}
		if err := diagnostics.CleanupErr(); err != nil {
			for i := range result {
				result[i].Evidence.Diagnostics = append(result[i].Evidence.Diagnostics, err.Error())
			}
			resultErr = errors.Join(resultErr, err)
		}
	}()

	stopCancel := context.AfterFunc(ctx, tabCancel)
	defer stopCancel()
	ctx, cancel := context.WithTimeout(tabCtx, s.timeout)
	defer cancel()

	var replayed atomic.Bool
	rewrite := func(e *fetch.EventRequestPaused) *fetch.ContinueRequestParams {
		continuation := fetch.ContinueRequest(e.RequestID)
		expected, _ := url.Parse(test.NavURL)
		actual, _ := url.Parse(e.Request.URL)
		if expected != nil && actual != nil {
			expected.Fragment = ""
			actual.Fragment = ""
			if expected.Path == "" {
				expected.Path = "/"
			}
			if actual.Path == "" {
				actual.Path = "/"
			}
		}
		if e.ResourceType == network.ResourceTypeDocument && expected != nil && actual != nil && expected.String() == actual.String() && replayed.CompareAndSwap(false, true) {
			continuation = continuation.WithMethod(target.HTTPMethod())
			if target.Body != "" {
				continuation = continuation.WithPostData(base64.StdEncoding.EncodeToString([]byte(target.Body)))
			}
		}
		return continuation
	}
	guard, policy := allocopts.GuardRequests(target.URL, cancel, rewrite)
	defer guard.Close()
	if err := chromedp.Run(ctx, policy); err != nil {
		return nil, err
	}
	if err := s.applyTargetState(ctx, target); err != nil {
		return nil, err
	}
	stopDialogs := allocopts.ListenDialogs(ctx, cancel, false, nil)
	defer stopDialogs()

	// Inject sink hooks via CDP before any navigation.
	// These hooks intercept innerHTML, eval, document.write, etc. and record
	// only when the xsscan marker passes through them — eliminating the false
	// positives from static source checks (marker-in-URL, marker-in-cookie, etc.).
	hookScript := buildHookScript(marker)
	injectHook := chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(hookScript).Do(ctx)
		return err
	})

	// Initialize source state in the target origin before application scripts.
	// about:blank storage is inaccessible and cannot seed target-origin storage.
	setup := test.Extra
	if test.Name == "referrer" {
		setup = fmt.Sprintf("Object.defineProperty(document,'referrer',{get:()=>%s});", jsStringLiteral(target.URL+"#"+marker+"="+payload))
	}
	if strings.HasPrefix(setup, "post-message-") || strings.HasPrefix(setup, "inject-inline-") {
		setup = ""
	}
	var actions []chromedp.Action
	if setup != "" {
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(setup).Do(ctx)
			return err
		}))
	}
	// Seed inputs before hooks so the scanner's own writes are never evidence.
	activity := &pageActivity{}
	chromedp.ListenTarget(ctx, activity.observe)
	actions = append(actions, injectHook, chromedp.Navigate(test.NavURL), chromedp.ActionFunc(func(ctx context.Context) error { return activity.wait(ctx, 2*time.Second) }))
	if test.Name == "postMessage" {
		actions = append(actions, chromedp.Evaluate(fmt.Sprintf("window.postMessage(%s,'*');", jsStringLiteral(marker+"="+payload)), nil), chromedp.ActionFunc(func(ctx context.Context) error { return activity.wait(ctx, time.Second) }))
	}
	err = chromedp.Run(ctx, actions...)

	if policyErr := guard.Err(); policyErr != nil {
		return nil, policyErr
	}
	if err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	var evidence hookEvidence
	if err := chromedp.Run(ctx, chromedp.Evaluate(`({installed: typeof window.__xsscan_hooks !== 'undefined', status: window.__xsscan_hook_status || {}, overflowed: window.__xsscan_hooks_overflowed === true, hits: window.__xsscan_hooks || []})`, &evidence)); err != nil {
		return nil, fmt.Errorf("read DOM sink evidence: %w", err)
	}
	if !evidence.Installed {
		return nil, fmt.Errorf("DOM sink instrumentation unavailable")
	}
	coverage := evidence.summarise()
	if len(plans) > 0 && plans[0] != nil {
		if err := collectDocumentPlan(ctx, plans[0]); err != nil {
			// Planning is supplemental: complete the original dynamic matrix
			// even if collection fails, then return this diagnostic as partial.
			plans[0].err = err
		}
	}
	var findings []model.Finding
	// The independent replay is a second full page load, so it is done once per test —
	// for the first recorded sink — rather than once per hit. It strengthens or leaves
	// the candidate alone; it never downgrades one, because a replay that cannot
	// reproduce the input shape says nothing about the observing run.
	replayDone := false
	for _, hit := range evidence.Hits {
		// Hooks match the full value before truncating the captured snippet.
		// Rechecking that snippet would lose markers outside the captured prefix.
		finding := newDOMFinding(test, payload,
			fmt.Sprintf("DOM (%s)", test.Name),
			fmt.Sprintf("DOM XSS candidate via %s: marker reached %s sink; execution not verified", test.Source, hit.Sink),
			"Use safe DOM APIs (textContent instead of innerHTML). Implement Trusted Types.",
			0.65, []string{"https://owasp.org/www-community/attacks/DOM_Based_Cross_Site_Scripting"})
		finding.Evidence = model.Evidence{DetectionMethod: "dom_sink_flow", Context: hit.Sink, Reflection: hit.Value}
		// Carry the marker's real position and the interval state so a reviewer can
		// tell where in the sink's input the marker landed, and whether the captured
		// window is complete. The snippet alone cannot express either.
		finding.Evidence.Interaction = describeSinkWindow(hit, coverage)
		// A DOM candidate is reproduced by restoring how the input reached the page,
		// not by re-sending a query parameter, so its provenance travels with it.
		attachReplayProvenance(&finding, test, marker)
		for _, flow := range test.Flows {
			if strings.TrimPrefix(flow.Sink, "window.") == hit.Sink {
				finding.Evidence.DataFlow = append(finding.Evidence.DataFlow, flow)
			}
		}
		if len(finding.Evidence.DataFlow) > 0 {
			finding.Evidence.AnalysisMethod = "sobek-source-sink+runtime-marker"
		}
		if !replayDone && s.replayOriginal {
			replayDone = true
			descriptor := replayDescriptorFor(test, marker)
			replay := s.replayDOMCandidate(ctx, target, finding, descriptor, payload)
			finding.Evidence.Interaction += "; independent replay: " + replay.Detail
			if replay.Err != nil {
				resultErr = errors.Join(resultErr, replay.Err)
			} else if replay.Outcome == replayError {
				resultErr = errors.Join(resultErr, fmt.Errorf("DOM replay incomplete: %s", replay.Detail))
			}
			if replay.confirmed() {
				// The original input reached the sink on its own, so this finding no
				// longer rests on the instrumented run alone. It is still not execution
				// proof — reaching a sink is not running — so the confidence stays below
				// the verified band.
				finding.Description += " [replayed with the unmarked payload]"
			}
		}
		findings = append(findings, finding)
	}

	return findings, resultErr
}

// newDOMFinding builds DOM sink candidates with their source.
// Sink flow alone does not verify execution.
func newDOMFinding(test domXSSTest, payload, parameter, description, remediation string, confidence float64, references []string) model.Finding {
	severity := model.High
	if confidence < 0.70 {
		severity = model.Medium
	}
	return model.Finding{
		Type:        model.DOMXSS,
		Severity:    severity,
		Confidence:  confidence,
		URL:         test.NavURL,
		Parameter:   parameter,
		ParamType:   model.ParamQuery,
		Payload:     payload,
		Contexts:    []string{"dom"},
		Description: description,
		Remediation: remediation,
		CWE:         "CWE-79",
		References:  references,
		Timestamp:   time.Now(),
	}
}
