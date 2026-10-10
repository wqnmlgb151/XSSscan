// Package dom provides headless browser-based DOM XSS detection.
// Uses Chrome DevTools Protocol (via chromedp) to navigate pages,
// inject JavaScript instrumentation, and detect dangerous sink executions.
package dom

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/xsscan/xsscan/pkg/analyze"
	allocopts "github.com/xsscan/xsscan/pkg/internal/chromedp"
	"github.com/xsscan/xsscan/pkg/model"
)

//go:embed hooks.js
var hookScript string

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
	s.auth = auth
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
	s.allocCancel()
	return nil
}

// domXSSTest represents a single DOM XSS source to test.
type domXSSTest struct {
	Name   string
	Source string // description of the source (fragment, search, etc.)
	NavURL string
	Extra  string // optional JS to execute before navigation (window.name, etc.)
}

// DetectDOMXSS tests multiple DOM XSS sources with the given payload.
// It covers: URL fragment, search parameters, document.referrer, window.name.
func (s *Scanner) DetectDOMXSS(ctx context.Context, target model.Target, payload string) ([]model.Finding, error) {
	u, err := url.Parse(target.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Build test URLs for different DOM XSS sources
	marker := analyze.GenerateMarker()
	tests := buildDOMTests(u, payload, marker)

	var allFindings []model.Finding
	var problems []error

	for _, test := range tests {
		if ctx.Err() != nil {
			return allFindings, errors.Join(append(problems, ctx.Err())...)
		}
		findings, err := s.runSingleDOMTest(ctx, target, test, marker, payload)
		if err != nil {
			problems = append(problems, fmt.Errorf("DOM source %s: %w", test.Name, err))
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, errors.Join(problems...)
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
func (s *Scanner) runSingleDOMTest(ctx context.Context, target model.Target, test domXSSTest, marker, payload string) (result []model.Finding, resultErr error) {
	tabCtx, tabCancel, diagnostics := allocopts.NewTabContext(s.allocCtx)
	defer tabCancel()
	defer func() {
		if err := diagnostics.Err(); err != nil {
			result = nil
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
	if err := chromedp.Run(ctx, policy, network.Enable()); err != nil {
		return nil, err
	}
	headers := network.Headers{}
	for key, value := range target.Headers {
		if !strings.EqualFold(key, "Proxy-Authorization") && !strings.EqualFold(key, "Content-Length") {
			headers[key] = value
		}
	}
	if err := chromedp.Run(ctx, network.SetExtraHTTPHeaders(headers)); err != nil {
		return nil, err
	}
	cookies := append([]*http.Cookie(nil), target.Cookies...)
	if s.auth != nil {
		cookies = append(append([]*http.Cookie(nil), s.auth.Cookies...), cookies...)
	}
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		set := network.SetCookie(cookie.Name, cookie.Value).WithURL(target.URL).WithPath(path).WithHTTPOnly(cookie.HttpOnly).WithSecure(cookie.Secure)
		if cookie.Domain != "" {
			set = set.WithDomain(cookie.Domain)
		}
		if err := chromedp.Run(ctx, set); err != nil {
			return nil, err
		}
	}
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			go func() { _ = chromedp.Run(ctx, page.HandleJavaScriptDialog(false)) }()
		}
	})

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
	actions := []chromedp.Action{injectHook}
	if setup != "" {
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(setup).Do(ctx)
			return err
		}))
	}
	actions = append(actions, chromedp.Navigate(test.NavURL), chromedp.Sleep(2*time.Second))
	if test.Name == "postMessage" {
		actions = append(actions, chromedp.Evaluate(fmt.Sprintf("window.postMessage(%s,'*');", jsStringLiteral(marker+"="+payload)), nil), chromedp.Sleep(time.Second))
	}
	err := chromedp.Run(ctx, actions...)

	if policyErr := guard.Err(); policyErr != nil {
		return nil, policyErr
	}
	if err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	var hooksInstalled bool
	var hookHits []sinkResult
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`typeof window.__xsscan_hooks !== 'undefined'`, &hooksInstalled),
		chromedp.Evaluate(`window.__xsscan_hooks || []`, &hookHits),
	); err != nil {
		return nil, fmt.Errorf("read DOM sink evidence: %w", err)
	}
	if !hooksInstalled {
		return nil, fmt.Errorf("DOM sink instrumentation unavailable")
	}
	var findings []model.Finding
	for _, hit := range hookHits {
		// Hooks match the full value before truncating the captured snippet.
		// Rechecking that snippet would lose markers outside the captured prefix.
		findings = append(findings, newDOMFinding(test, payload,
			fmt.Sprintf("DOM (%s)", test.Name),
			fmt.Sprintf("DOM XSS candidate via %s: marker reached %s sink; execution not verified", test.Source, hit.Sink),
			"Use safe DOM APIs (textContent instead of innerHTML). Implement Trusted Types.",
			0.85, []string{"https://owasp.org/www-community/attacks/DOM_Based_Cross_Site_Scripting"}))
	}

	return findings, nil
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
