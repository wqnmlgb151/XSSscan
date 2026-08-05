// Package dom provides headless browser-based DOM XSS detection.
// Uses Chrome DevTools Protocol (via chromedp) to navigate pages,
// inject JavaScript instrumentation, and detect dangerous sink executions.
package dom

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
)

//go:embed sinks.js
var sinkDetectionScript string

//go:embed hooks.js
var hookScript string

// buildSinkScript injects the marker into the sink detection template.
func buildSinkScript(marker string) string {
	return strings.Replace(sinkDetectionScript, "{{MARKER}}", marker, 1)
}

// buildHookScript injects the marker into the CDP sink hook script.
func buildHookScript(marker string) string {
	return strings.Replace(hookScript, "__MARKER_PLACEHOLDER__", marker, 1)
}

// sinkResult is a single recorded sink hit from the hooks.js instrumentation.
type sinkResult struct {
	Sink  string `json:"sink"`
	Value string `json:"value"`
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
}

// AuthState carries authentication context for DOM scanning.
// It seeds the browser's cookie jar before navigation so that
// authenticated SPAs and protected endpoints are reachable.
type AuthState struct {
	Cookies []*http.Cookie
	Headers map[string]string
}

// NewScanner creates a new headless browser scanner.
func NewScanner(ctx context.Context, timeout time.Duration) (*Scanner, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	opts := append([]chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.IgnoreCertErrors,
		chromedp.WindowSize(1280, 800),
	}, chromedp.DefaultExecAllocatorOptions[:]...)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)

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
	s.auth = auth
	return s, nil
}

// ApplyAuthState navigates to the target domain and sets cookies via JavaScript evaluation.
// This seeds the browser's cookie jar with session/auth cookies before DOM XSS testing.
func (s *Scanner) ApplyAuthState(ctx context.Context, targetURL string) error {
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

	tabCtx, tabCancel := chromedp.NewContext(s.allocCtx)
	defer tabCancel()
	withTimeout, cancel := context.WithTimeout(tabCtx, s.timeout)
	defer cancel()

	// Navigate to the target domain first so document.cookie works
	if err := chromedp.Run(withTimeout, chromedp.Navigate(targetURL)); err != nil {
		return fmt.Errorf("auth state navigation failed: %w", err)
	}

	for _, cookie := range s.auth.Cookies {
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
	s.allocCancel()
	return nil
}

// domXSSTest represents a single DOM XSS source to test.
type domXSSTest struct {
	Name    string
	Source  string // description of the source (fragment, search, etc.)
	NavURL  string
	Extra   string // optional JS to execute before navigation (window.name, etc.)
}

// DetectDOMXSS tests multiple DOM XSS sources with the given payload.
// It covers: URL fragment, search parameters, document.referrer, window.name.
func (s *Scanner) DetectDOMXSS(ctx context.Context, target model.Target, payload string) ([]model.Finding, error) {
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Build test URLs for different DOM XSS sources
	marker := analyze.MarkerPrefix
	tests := buildDOMTests(u, payload, marker)

	var allFindings []model.Finding

	for _, test := range tests {
		findings, err := s.runSingleDOMTest(ctx, target, test, marker)
		if err != nil {
			continue // skip failed tests, don't fail the entire scan
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// buildDOMTests creates test configurations for various DOM XSS sources.
// Covers the OWASP DOM XSS taxonomy: fragment, search, pathname, referrer, window.name,
// javascript: protocol href, inline event handler injection, localStorage/sessionStorage,
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
			Extra:  fmt.Sprintf("window.name=%s;", jsStringLiteral(markerPayload)),
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
			Name:   "inline-event",
			Source: "inline event handler injection via DOM",
			NavURL: buildURLWithFragment(u, "inline-event-test"),
			// Inject an element with an inline event handler containing the marker.
			// The onerror fires automatically (invalid image src), executing the handler.
			// If the page processes dynamically-added elements (event delegation,
			// jQuery .on(), etc.), this tests whether injected handlers execute.
			Extra:  "inject-inline-" + marker,
		},
		{
			Name:   "localStorage",
			Source: "localStorage.getItem (SPA state persistence)",
			NavURL: buildURLWithFragment(u, "localstorage-test"),
			// Store marker+payload into localStorage before page load.
			// SPA apps often read from localStorage and render with innerHTML/v-html.
			Extra:  fmt.Sprintf("localStorage.setItem(%s,%s);", jsStringLiteral(marker), jsStringLiteral(payload)),
		},
		{
			Name:   "sessionStorage",
			Source: "sessionStorage.getItem (tab-level state)",
			NavURL: buildURLWithFragment(u, "sessionstorage-test"),
			// Same as localStorage but scoped to a single tab/session.
			Extra:  fmt.Sprintf("sessionStorage.setItem(%s,%s);", jsStringLiteral(marker), jsStringLiteral(payload)),
		},
		{
			Name:   "document-cookie",
			Source: "document.cookie (non-HttpOnly cookie)",
			NavURL: buildURLWithFragment(u, "cookie-test"),
			// Set a cookie containing the marker. If the page reads document.cookie
			// and renders it unsanitized, this triggers DOM XSS.
			// The cookie domain is set to the target host so it's readable by JS.
			Extra:  fmt.Sprintf("document.cookie=%s; domain=%s", jsStringLiteral(markerPayload), u.Hostname()),
		},
		{
			Name:   "postMessage",
			Source: "window.postMessage (cross-origin messaging)",
			NavURL: buildURLWithFragment(u, "postmessage-test"),
			// postMessage sends data to the page's message event listener.
			// If the page does eval(message.data) or innerHTML = e.data, this triggers.
			// We send after page load so the listener is registered.
			Extra:  fmt.Sprintf("post-message-%s", marker),
		},
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
func (s *Scanner) runSingleDOMTest(ctx context.Context, target model.Target, test domXSSTest, marker string) ([]model.Finding, error) {
	tabCtx, tabCancel := chromedp.NewContext(s.allocCtx)
	defer tabCancel()

	ctx, cancel := context.WithTimeout(tabCtx, s.timeout)
	defer cancel()

	// Inject sink hooks via CDP before any navigation.
	// These hooks intercept innerHTML, eval, document.write, etc. and record
	// only when the xsscan marker passes through them — eliminating the false
	// positives from static source checks (marker-in-URL, marker-in-cookie, etc.).
	hookScript := buildHookScript(marker)
	injectHook := chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(hookScript).Do(ctx)
		return err
	})

	var consoleMsgs []string
	var exceptions []string

	// Listen for console and exception events
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			for _, arg := range e.Args {
				if arg.Value != nil {
					consoleMsgs = append(consoleMsgs, string(arg.Value))
				}
			}
		case *runtime.EventExceptionThrown:
			if e.ExceptionDetails != nil && e.ExceptionDetails.Exception != nil {
				exceptions = append(exceptions, e.ExceptionDetails.Exception.Description)
			}
		}
	})

	// For tests requiring pre-navigation setup (window.name, referrer),
	// first load the page, inject state, then navigate to the target.
	var err error
	switch {
	case test.Extra != "" && test.Name == "window.name":
		// window.name persists across navigations — set it on about:blank first
		err = chromedp.Run(ctx,
			injectHook,
			chromedp.Navigate("about:blank"),
			chromedp.Evaluate(test.Extra, nil),
			chromedp.Navigate(test.NavURL),
			chromedp.Sleep(2*time.Second),
		)
	case test.Extra != "" && test.Name == "referrer":
		// document.referrer test — load a spoofing page first.
		// Use DOM APIs instead of document.write to prevent Self-XSS:
		// user-controlled URL could contain single quotes that break
		// out of a JS string literal and execute arbitrary code.
		referrerJS := fmt.Sprintf(`(function(){var m=document.createElement('meta');m.name='referrer';m.content='unsafe-url';document.head.appendChild(m);var f=document.createElement('iframe');f.src=%s;document.body.appendChild(f);})();`, strconv.Quote(test.NavURL))
		err = chromedp.Run(ctx,
			injectHook,
			chromedp.Navigate("about:blank"),
			chromedp.Evaluate(referrerJS, nil),
			chromedp.Sleep(2*time.Second),
		)
	case test.Extra != "" && test.Name == "inline-event":
		// Inline event handler test — navigate to page, then inject an element
		// with an inline event handler. The onerror fires automatically (invalid src),
		// testing whether dynamically-injected inline handlers execute in this context.
		err = chromedp.Run(ctx,
			injectHook,
			chromedp.Navigate(test.NavURL),
			chromedp.Sleep(1*time.Second),
			chromedp.Evaluate(fmt.Sprintf(`(function(){
				var img = document.createElement('img');
				img.src = 'x';
				img.setAttribute('onerror', 'this.dataset.%s=1; document.body.setAttribute("data-%s-fired", "1");');
				document.body.appendChild(img);
			})();`, marker, marker), nil),
			chromedp.Sleep(2*time.Second),
		)
	case strings.HasPrefix(test.Extra, "localStorage.setItem") ||
		strings.HasPrefix(test.Extra, "sessionStorage.setItem") ||
		strings.HasPrefix(test.Extra, "document.cookie"):
		// Storage-based sources — set value on about:blank first (storage
		// is origin-scoped), then navigate to target so the page reads it.
		err = chromedp.Run(ctx,
			injectHook,
			chromedp.Navigate("about:blank"),
			chromedp.Evaluate(test.Extra, nil),
			chromedp.Navigate(test.NavURL),
			chromedp.Sleep(2*time.Second),
		)
	case strings.HasPrefix(test.Extra, "post-message-"):
		// postMessage source — navigate to target first so the message
		// listener is registered, then post a message containing the marker.
		postJS := fmt.Sprintf(`window.postMessage(%s, "*");`, jsStringLiteral(marker))
		err = chromedp.Run(ctx,
			injectHook,
			chromedp.Navigate(test.NavURL),
			chromedp.Sleep(1*time.Second),
			chromedp.Evaluate(postJS, nil),
			chromedp.Sleep(2*time.Second),
		)
	default:
		// Standard navigation for fragment, search, pathname tests
		err = chromedp.Run(ctx,
			injectHook,
			chromedp.Navigate(test.NavURL),
			chromedp.Sleep(2*time.Second),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	var findings []model.Finding

	// Read CDP sink hooks first — these provide the highest-quality signal
	// (marker actually passed through innerHTML/eval/document.write, not just
	// sitting in the URL or cookie).
	var hookHits []sinkResult
	if err := chromedp.Run(ctx, chromedp.Evaluate(`window.__xsscan_hooks || []`, &hookHits)); err == nil {
		for _, hit := range hookHits {
			findings = append(findings, model.Finding{
				Type:        model.DOMXSS,
				Severity:    model.High,
				Confidence:  0.85, // higher confidence: proven sink execution
				URL:         test.NavURL,
				Parameter:   fmt.Sprintf("DOM (%s)", test.Name),
				ParamType:   model.ParamQuery,
				Payload:     test.NavURL,
				Contexts:    []string{"dom"},
				Description: fmt.Sprintf("DOM XSS via %s: marker reached %s sink", test.Source, hit.Sink),
				Remediation: "Use safe DOM APIs (textContent instead of innerHTML). Implement Trusted Types.",
				CWE:         "CWE-79",
				References: []string{
					"https://owasp.org/www-community/attacks/DOM_Based_Cross_Site_Scripting",
				},
				Timestamp: time.Now(),
			})
		}
	}

	// Fallback: sink detection via embedded JS (post-hoc DOM scan).
	// Only used when hooks didn't catch anything (older browsers or
	// hook interference). Reports markers that appear in dangerous
	// DOM contexts, not just anywhere in the page.
	if len(hookHits) == 0 {
		var sinkHit string
		err = chromedp.Run(ctx,
			chromedp.Evaluate(buildSinkScript(marker), &sinkHit),
		)
		if err != nil {
			return nil, fmt.Errorf("JS evaluation failed: %w", err)
		}

		if sinkHit != "" {
		findings = append(findings, model.Finding{
			Type:        model.DOMXSS,
			Severity:    model.High,
			Confidence:  0.75,
			URL:         test.NavURL,
			Parameter:   fmt.Sprintf("DOM (%s)", test.Name),
			ParamType:   model.ParamQuery,
			Payload:     test.NavURL,
			Contexts:    []string{"dom"},
			Description: fmt.Sprintf("DOM XSS via %s: payload reached sink(s): %s", test.Source, sinkHit),
			Remediation: "Use safe DOM APIs (textContent instead of innerHTML). Sanitize all client-side input. Implement Trusted Types.",
			CWE:         "CWE-79",
			References: []string{
				"https://owasp.org/www-community/attacks/DOM_Based_Cross_Site_Scripting",
				"https://portswigger.net/web-security/dom-based",
			},
			Timestamp: time.Now(),
		})
	}
	} // end if len(hookHits) == 0

	// Check console for payload execution indicators
	for _, msg := range consoleMsgs {
		if strings.Contains(msg, marker) {
			findings = append(findings, model.Finding{
				Type:        model.DOMXSS,
				Severity:    model.Medium,
				Confidence:  0.60,
				URL:         test.NavURL,
				Parameter:   fmt.Sprintf("DOM (%s/console)", test.Name),
				ParamType:   model.ParamQuery,
				Payload:     test.NavURL,
				Contexts:    []string{"dom"},
				Description: fmt.Sprintf("DOM XSS indicator via %s: payload in console: %s", test.Source, text.Truncate(msg, 100)),
				Remediation: "Review client-side JavaScript that processes URL input.",
				CWE:         "CWE-79",
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

