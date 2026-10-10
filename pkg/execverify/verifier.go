// Package execverify provides browser-based execution verification for reflected XSS findings.
// Uses chromedp to inject payloads into real Chrome and detect dialog execution.
package execverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	allocopts "github.com/xsscan/xsscan/pkg/internal/chromedp"
	"github.com/xsscan/xsscan/pkg/internal/request"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// ExecutionResult holds the outcome of browser-based execution verification.
type ExecutionResult struct {
	VerificationPayload string   // exact instrumented probe sent for correlation
	Executed            bool     // true if alert/confirm/prompt was called
	DialogType          string   // "alert" | "confirm" | "prompt"
	DialogMessage       string   // the message passed to the dialog
	ConsoleErrors       []string // JS console errors observed
	DOMMutations        []string // observed DOM changes (tag names injected)
	Confidence          float64  // 0.0-1.0 execution confidence
	ScreenshotPath      string   // path to proof screenshot (empty if none)
	Interaction         string   // controlled focus/mouseover used for this candidate
	LoadError           string   // page load error if any
}

// Verifier manages a headless Chrome instance for XSS execution verification.
type Verifier struct {
	allocCtx      context.Context
	allocCancel   context.CancelFunc
	timeout       time.Duration
	auth          *AuthState
	screenshotDir string
	consoleMu     sync.Mutex
}

// AuthState carries authentication context for verification.
type AuthState struct {
	Cookies []*http.Cookie
}

// NewVerifier creates a new browser verifier.
func NewVerifier(ctx context.Context, timeout time.Duration) (*Verifier, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	allocCtx, allocCancel := allocopts.NewExecAllocator(ctx, allocopts.StandardHeadlessOptions...)

	tmpDir := filepath.Join(os.TempDir(), "xsscan-screenshots")
	os.MkdirAll(tmpDir, 0755)

	return &Verifier{
		allocCtx:      allocCtx,
		allocCancel:   allocCancel,
		timeout:       timeout,
		screenshotDir: tmpDir,
	}, nil
}

// NewVerifierWithAuth creates a verifier with authentication state.
func NewVerifierWithAuth(ctx context.Context, timeout time.Duration, auth *AuthState) (*Verifier, error) {
	v, err := NewVerifier(ctx, timeout)
	if err != nil {
		return nil, err
	}
	v.auth = auth
	return v, nil
}

// Close terminates the browser and releases resources.
func (v *Verifier) Close() error {
	v.allocCancel()
	return nil
}

// VerifyFinding verifies a reflected XSS finding by injecting its payload
// into a real browser and checking whether JavaScript executes.
func (v *Verifier) VerifyFinding(ctx context.Context, finding model.Finding, target model.Target) (*ExecutionResult, error) {
	var err error
	target, err = capturedTarget(finding.Evidence.HTTP, target)
	if err != nil {
		return nil, err
	}
	return v.VerifyPayload(ctx, target, finding.Parameter, finding.ParamType, finding.Payload)
}

// VerifyPayload verifies a specific payload against a target parameter.
func (v *Verifier) VerifyPayload(ctx context.Context, target model.Target, paramName string, paramType model.ParamType, payload string) (result *ExecutionResult, err error) {
	result = &ExecutionResult{}
	payload, message, err := InstrumentDialogPayload(payload)
	if err != nil {
		return result, err
	}
	defer func() {
		if result != nil {
			result.VerificationPayload = payload
		}
	}()
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, target.URL); err != nil {
		return nil, err
	}
	if paramType == model.ParamBody || paramType == model.ParamHeader || paramType == model.ParamCookie {
		return v.verifyRequest(ctx, target, paramName, paramType, payload, message)
	}

	// Build the target URL/navigation based on parameter type
	navURL, err := v.buildNavigationURL(target, paramName, paramType, payload)
	if err != nil {
		return nil, fmt.Errorf("build navigation URL: %w", err)
	}
	if target.HTTPMethod() != http.MethodGet || target.Body != "" || len(target.Headers) > 0 || len(target.Cookies) > 0 {
		target.URL = navURL
		return v.verifyRequest(ctx, target, "", "", "", message)
	}
	return v.runBrowserCheckMatching(ctx, navURL, result, message)
}

// VerifyStoredPage visits the trigger without resubmitting the saved payload.
func (v *Verifier) VerifyStoredPage(ctx context.Context, target model.Target, message string) (*ExecutionResult, error) {
	if message == "" {
		return nil, fmt.Errorf("stored execution message is empty")
	}
	if err := ssrfguard.IsURLTargetAllowedContext(ctx, target.URL); err != nil {
		return nil, err
	}
	target.Method = http.MethodGet
	target.Body = ""
	return v.verifyRequest(ctx, target, "", "", "", message)
}

// buildNavigationURL creates a URL with the payload injected at the right position.
func (v *Verifier) buildNavigationURL(target model.Target, paramName string, paramType model.ParamType, payload string) (string, error) {
	u, err := url.Parse(target.URL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}

	switch paramType {
	case model.ParamQuery:
		values := u.Query()
		values.Set(paramName, payload)
		u.RawQuery = values.Encode()
		return u.String(), nil

	case model.ParamPath:
		return request.InjectPathValue(target.URL, paramName, "", payload)

	default:
		return "", fmt.Errorf("parameter type %s requires proxy verification", paramType)
	}
}

// runBrowserCheck navigates to the URL and checks for dialog execution.
func (v *Verifier) runBrowserCheck(ctx context.Context, navURL string, result *ExecutionResult, rewrites ...allocopts.RequestRewrite) (*ExecutionResult, error) {
	return v.runBrowserCheckMatching(ctx, navURL, result, "", rewrites...)
}

func (v *Verifier) runBrowserCheckMatching(ctx context.Context, navURL string, result *ExecutionResult, message string, rewrites ...allocopts.RequestRewrite) (out *ExecutionResult, resultErr error) {
	tabCtx, tabCancel, diagnostics := allocopts.NewTabContext(v.allocCtx)
	defer tabCancel()
	defer func() {
		if err := diagnostics.Err(); err != nil {
			result.Executed = false
			result.Confidence = 0
			result.LoadError = err.Error()
			out = result
			resultErr = errors.Join(resultErr, err)
		}
	}()
	stopCancel := context.AfterFunc(ctx, tabCancel)
	defer stopCancel()

	tctx, cancel := context.WithTimeout(tabCtx, v.timeout)
	defer cancel()

	// Listen before navigation, including authenticated navigation. CDP events
	// survive document changes and detect synchronous as well as async dialogs.
	dialogDetected := make(chan dialogInfo, 1)
	var consoleErrors []string
	v.installConsoleHandler(tctx, &consoleErrors, dialogDetected, message)
	var rewrite allocopts.RequestRewrite
	if len(rewrites) > 0 {
		rewrite = rewrites[0]
	}
	guard, policy := allocopts.GuardRequests(navURL, cancel, rewrite)
	if err := chromedp.Run(tctx, policy); err != nil {
		return result, fmt.Errorf("browser setup: %w", err)
	}

	// Apply auth cookies without navigating to the payload URL first.
	if v.auth != nil && len(v.auth.Cookies) > 0 {
		if err := v.applyCookies(tctx, navURL); err != nil {
			return result, fmt.Errorf("auth cookie error: %w", err)
		}
	}

	// Navigate and wait for page load + async handlers
	var loadErr error
	err := chromedp.Run(tctx,
		chromedp.Navigate(navURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(3*time.Second), // wait for async handlers (onload, setTimeout, etc.)
	)
	if err != nil {
		loadErr = err
		result.LoadError = err.Error()
	}

	if message != "" && loadErr == nil && len(dialogDetected) == 0 {
		// Dispatch only to handlers carrying this exact candidate token; no click,
		// form submission, or direct evaluation of submitted payload source.
		encoded, _ := json.Marshal(message)
		script := fmt.Sprintf(`(() => {
    const token=%s; let actions=[]; let count=0;
    for(const el of document.querySelectorAll('[onfocus],[onmouseover]')) {
      const focus=(el.getAttribute('onfocus')||'').includes(token);
      const hover=(el.getAttribute('onmouseover')||'').includes(token);
      if(!focus && !hover) continue;
      if(count++ >= 16) break;
      if(focus) {el.focus();actions.push('focus');}
      if(hover) {el.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));actions.push('synthetic mouseover');}
    }
    return [...new Set(actions)].join(', ');
  })()`, encoded)
		if err := chromedp.Run(tctx, chromedp.Evaluate(script, &result.Interaction), chromedp.Sleep(100*time.Millisecond)); err != nil {
			loadErr = err
			result.LoadError = err.Error()
		}
	}

	// Check if a dialog was detected
	select {
	case d := <-dialogDetected:
		result.Executed = true
		result.DialogType = d.dialogType
		result.DialogMessage = d.message
		result.Confidence = 0.95
	case <-time.After(100 * time.Millisecond):
		// No dialog detected
	}

	result.ConsoleErrors = v.consoleLoad(&consoleErrors)

	// Capture screenshot if execution was detected
	if result.Executed && result.Confidence >= 0.9 {
		screenshotPath := filepath.Join(v.screenshotDir,
			fmt.Sprintf("xsscan-proof-%d.png", time.Now().UnixNano()))
		var buf []byte
		if err := chromedp.Run(tctx, chromedp.CaptureScreenshot(&buf)); err == nil {
			if err := os.WriteFile(screenshotPath, buf, 0600); err == nil {
				result.ScreenshotPath = screenshotPath
			}
		}
	}

	if policyErr := guard.Err(); policyErr != nil {
		result.Executed = false
		result.Confidence = 0
		return result, policyErr
	}
	if loadErr != nil {
		result.Executed = false
		result.Confidence = 0
		return result, fmt.Errorf("navigation failed: %w", loadErr)
	}

	return result, nil
}

// dialogInfo holds information about a detected dialog call.
type dialogInfo struct {
	dialogType string
	message    string
}

// installConsoleHandler captures JavaScript console errors.
func (v *Verifier) installConsoleHandler(ctx context.Context, errors *[]string, detected chan<- dialogInfo, expected ...string) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if e, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			matched := len(expected) == 0 || expected[0] == "" || e.Message == expected[0]
			if matched && (e.Type == page.DialogTypeAlert || e.Type == page.DialogTypeConfirm || e.Type == page.DialogTypePrompt) {
				select {
				case detected <- dialogInfo{dialogType: string(e.Type), message: e.Message}:
				default:
				}
			}
			// Auto-dismiss any real dialogs
			go func() {
				chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
			}()
			v.consoleMu.Lock()
			*errors = append(*errors, fmt.Sprintf("JS dialog: %s", e.Message))
			v.consoleMu.Unlock()
		}
	})
}

// consoleLoad safely reads console errors under the mutex.
func (v *Verifier) consoleLoad(errors *[]string) []string {
	v.consoleMu.Lock()
	defer v.consoleMu.Unlock()
	return append([]string(nil), (*errors)...)
}

// applyCookies sets authentication cookies in the browser.
func (v *Verifier) applyCookies(ctx context.Context, targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}

	for _, cookie := range v.auth.Cookies {
		if cookie == nil {
			continue
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		set := network.SetCookie(cookie.Name, cookie.Value).WithURL(targetURL).
			WithPath(path).WithHTTPOnly(cookie.HttpOnly).WithSecure(cookie.Secure)
		if cookie.Domain != "" {
			set = set.WithDomain(cookie.Domain)
		}
		if err := chromedp.Run(ctx, set); err != nil {
			return fmt.Errorf("set cookie %s: %w", cookie.Name, err)
		}
	}
	return nil
}

// parseDialogJSON parses a JSON dialog detection result.
// Format: {"type":"alert","message":"1"}
func parseDialogJSON(s string) dialogInfo {
	var info dialogInfo
	if len(s) < 10 {
		return info
	}
	// Use a minimal struct for robust parsing — handles escaped quotes,
	// whitespace variations, and field reordering correctly.
	var parsed struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(s), &parsed); err == nil {
		info.dialogType = parsed.Type
		info.message = parsed.Message
	}
	return info
}

// splitPath splits a URL path into segments.
// Preserves the leading empty segment for absolute paths
// (e.g., "/a/b" → ["", "a", "b"], "/" → [""]).
func splitPath(p string) []string {
	if p == "/" {
		return []string{""}
	}
	if p == "" {
		return []string{""}
	}
	return strings.Split(p, "/")
}

// joinPath joins path segments back together with "/" separators.
func joinPath(segments []string) string {
	return strings.Join(segments, "/")
}
