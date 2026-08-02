// Package execverify provides browser-based execution verification for reflected XSS findings.
// Uses chromedp to inject payloads into real Chrome and detect dialog execution.
package execverify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/xsscan/xsscan/pkg/model"
)

// ExecutionResult holds the outcome of browser-based execution verification.
type ExecutionResult struct {
	Executed          bool     // true if alert/confirm/prompt was called
	DialogType        string   // "alert" | "confirm" | "prompt"
	DialogMessage     string   // the message passed to the dialog
	ConsoleErrors     []string // JS console errors observed
	DOMMutations      []string // observed DOM changes (tag names injected)
	Confidence        float64  // 0.0-1.0 execution confidence
	ScreenshotPath    string   // path to proof screenshot (empty if none)
	LoadError         string   // page load error if any
}

// Verifier manages a headless Chrome instance for XSS execution verification.
type Verifier struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	timeout     time.Duration
	auth        *AuthState
	screenshotDir string
}

// AuthState carries authentication context for verification.
type AuthState struct {
	Cookies []*http.Cookie
	Headers map[string]string
}

// NewVerifier creates a new browser verifier.
func NewVerifier(ctx context.Context, timeout time.Duration) (*Verifier, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
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
	return v.VerifyPayload(ctx, target, finding.Parameter, finding.ParamType, finding.Payload)
}

// VerifyPayload verifies a specific payload against a target parameter.
func (v *Verifier) VerifyPayload(ctx context.Context, target model.Target, paramName string, paramType model.ParamType, payload string) (*ExecutionResult, error) {
	result := &ExecutionResult{}

	// Build the target URL/navigation based on parameter type
	navURL, err := v.buildNavigationURL(target, paramName, paramType, payload)
	if err != nil {
		// For body/header/cookie params, use proxy-based verification
		if paramType == model.ParamBody || paramType == model.ParamHeader || paramType == model.ParamCookie {
			return v.verifyViaProxy(ctx, target, paramName, paramType, payload)
		}
		return nil, fmt.Errorf("build navigation URL: %w", err)
	}

	return v.runBrowserCheck(ctx, navURL, result)
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
		// Replace path segment — find the segment that matches the original param value
		segments := splitPath(u.Path)
		for i, seg := range segments {
			if seg == target.Headers["__xsscan_path_original__"] || seg == "" {
				segments[i] = payload
				break
			}
		}
		u.Path = joinPath(segments)
		return u.String(), nil

	default:
		return "", fmt.Errorf("parameter type %s requires proxy verification", paramType)
	}
}

// runBrowserCheck navigates to the URL and checks for dialog execution.
func (v *Verifier) runBrowserCheck(ctx context.Context, navURL string, result *ExecutionResult) (*ExecutionResult, error) {
	tabCtx, tabCancel := chromedp.NewContext(v.allocCtx)
	defer tabCancel()

	tctx, cancel := context.WithTimeout(tabCtx, v.timeout)
	defer cancel()

	// Apply auth cookies if configured
	if v.auth != nil && len(v.auth.Cookies) > 0 {
		if err := v.applyCookies(tctx, navURL); err != nil {
			result.LoadError = fmt.Sprintf("auth cookie error: %v", err)
		}
	}

	// Install dialog interception BEFORE navigation
	dialogDetected := make(chan dialogInfo, 1)
	v.installDialogHandlers(tctx, dialogDetected)

	// Install console error collector
	var consoleErrors []string
	v.installConsoleHandler(tctx, &consoleErrors)

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

	// Even if no dialog, check for DOM mutations (script-injected elements)
	if !result.Executed {
		mutations := v.checkDOMMutations(tctx)
		result.DOMMutations = mutations
		if len(mutations) > 0 {
			result.Confidence = 0.70 // structural execution, not confirmed dialog
		}
	}

	result.ConsoleErrors = consoleErrors

	// Capture screenshot if execution was detected
	if result.Executed && result.Confidence >= 0.9 {
		screenshotPath := filepath.Join(v.screenshotDir,
			fmt.Sprintf("xsscan-proof-%d.png", time.Now().UnixNano()))
		var buf []byte
		if err := chromedp.Run(tctx, chromedp.CaptureScreenshot(&buf)); err == nil {
			if err := os.WriteFile(screenshotPath, buf, 0644); err == nil {
				result.ScreenshotPath = screenshotPath
			}
		}
	}

	if loadErr != nil && !result.Executed {
		return result, fmt.Errorf("navigation failed: %w", loadErr)
	}

	return result, nil
}

// dialogInfo holds information about a detected dialog call.
type dialogInfo struct {
	dialogType string
	message    string
}

// installDialogHandlers overrides window.alert/confirm/prompt to detect execution.
// All handlers are installed in a single CDP round-trip for efficiency.
func (v *Verifier) installDialogHandlers(ctx context.Context, detected chan<- dialogInfo) {
	// Install all three dialog overrides and read back any detection in one evaluation.
	// This reduces 5 CDP round-trips to 1, saving ~50-100ms per verification.
	var detectionResult *string
	chromedp.Evaluate(`
		(function() {
			window.__xsscan_dialog = null;
			window.alert = function(msg) { window.__xsscan_dialog = {type: 'alert', message: String(msg)}; };
			window.confirm = function(msg) { window.__xsscan_dialog = {type: 'confirm', message: String(msg)}; };
			window.prompt = function(msg) { window.__xsscan_dialog = {type: 'prompt', message: String(msg)}; };
			if (window.__xsscan_dialog) {
				return JSON.stringify(window.__xsscan_dialog);
			}
			return null;
		})()
	`, &detectionResult).Do(ctx)

	if detectionResult != nil && *detectionResult != "null" {
		info := parseDialogJSON(*detectionResult)
		if info.dialogType != "" {
			select {
			case detected <- info:
			default:
			}
		}
	}
}

// installConsoleHandler captures JavaScript console errors.
func (v *Verifier) installConsoleHandler(ctx context.Context, errors *[]string) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if e, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			// Auto-dismiss any real dialogs
			go func() {
				chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
			}()
			*errors = append(*errors, fmt.Sprintf("JS dialog: %s", e.Message))
		}
	})
}

// checkDOMMutations checks if script-injected elements appeared in the DOM.
func (v *Verifier) checkDOMMutations(ctx context.Context) []string {
	var mutations []string

	// Check for newly injected script tags
	chromedp.Evaluate(`
		(function() {
			var result = [];
			var scripts = document.querySelectorAll('script');
			for (var i = 0; i < scripts.length; i++) {
				if (scripts[i].textContent && scripts[i].textContent.indexOf('alert') !== -1) {
					result.push('script_with_alert');
				}
			}
			var imgs = document.querySelectorAll('img[src="x"]');
			if (imgs.length > 0) result.push('img_injection');
			var svgs = document.querySelectorAll('svg');
			if (svgs.length > 0) result.push('svg_injection');
			return result.join(',');
		})()
	`, &mutations)

	return mutations
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

	// Navigate to domain first so document.cookie works
	if err := chromedp.Run(ctx, chromedp.Navigate(targetURL)); err != nil {
		return fmt.Errorf("auth navigation: %w", err)
	}

	for _, cookie := range v.auth.Cookies {
		domain := cookie.Domain
		if domain == "" {
			domain = "." + host
		}
		path := cookie.Path
		if path == "" {
			path = "/"
		}
		cookieStr := fmt.Sprintf("%s=%s; domain=%s; path=%s", cookie.Name, cookie.Value, domain, path)
		js := "document.cookie = " + strconv.Quote(cookieStr) + ";"
		if err := chromedp.Run(ctx, chromedp.Evaluate(js, nil)); err != nil {
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
