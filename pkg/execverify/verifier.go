// Package execverify provides browser-based execution verification for reflected XSS findings.
// Uses chromedp to inject payloads into real Chrome and detect dialog execution.
package execverify

import (
	"context"
	"crypto/rand"
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

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	allocopts "github.com/wqnmlgb151/XSSscan/pkg/internal/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/internal/privatefs"
	"github.com/wqnmlgb151/XSSscan/pkg/internal/request"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
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
	allocCtx           context.Context
	allocCancel        context.CancelFunc
	timeout            time.Duration
	auth               *AuthState
	screenshotDir      string
	screenshotErr      error
	captureScreenshots bool
	screenshotMu       sync.Mutex
	screenshotClosed   bool
	screenshotCloseErr error
	screenshotStop     func() bool
	consoleMu          sync.Mutex
	browserOnce        sync.Once
	browserCtx         context.Context
	browserCancel      context.CancelFunc
	browserErr         error
}

// AuthState carries authentication context for verification.
type AuthState struct {
	Cookies []*http.Cookie
}

// NewVerifier creates a new browser verifier.
func NewVerifier(ctx context.Context, timeout time.Duration) (*Verifier, error) {
	return NewVerifierWithOptions(ctx, timeout, VerifierOptions{})
}

type VerifierOptions struct {
	// CaptureScreenshots is opt-in because images may contain credentials/PII.
	// Returned paths are private temporary evidence, valid only until Close or cancellation.
	CaptureScreenshots bool
}

func NewVerifierWithOptions(ctx context.Context, timeout time.Duration, options VerifierOptions) (*Verifier, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	allocCtx, allocCancel := allocopts.NewExecAllocator(ctx, allocopts.StandardHeadlessOptions...)

	var tmpDir string
	var screenshotErr error
	if options.CaptureScreenshots {
		tmpDir, screenshotErr = privatefs.TempDir("", "xsscan-screenshots-")
	}

	v := &Verifier{
		allocCtx:           allocCtx,
		allocCancel:        allocCancel,
		timeout:            timeout,
		screenshotDir:      tmpDir,
		screenshotErr:      screenshotErr,
		captureScreenshots: options.CaptureScreenshots,
	}
	if options.CaptureScreenshots {
		v.screenshotStop = context.AfterFunc(ctx, func() { _ = v.cleanupScreenshots() })
	}
	return v, nil
}

// NewVerifierWithAuth creates a verifier with authentication state.
func NewVerifierWithAuth(ctx context.Context, timeout time.Duration, auth *AuthState) (*Verifier, error) {
	v, err := NewVerifier(ctx, timeout)
	if err != nil {
		return nil, err
	}
	if auth != nil {
		v.auth = &AuthState{Cookies: request.CloneCookies(auth.Cookies)}
	}
	return v, nil
}

// Close terminates the browser and releases resources.
func (v *Verifier) Close() error {
	if v.screenshotStop != nil {
		v.screenshotStop()
	}
	err := v.cleanupScreenshots()
	v.allocCancel()
	// Join initialization before reading browserCancel, including concurrent Close.
	v.browserOnce.Do(func() { v.browserErr = context.Canceled })
	if v.browserCancel != nil {
		v.browserCancel()
	}
	return err
}

func (v *Verifier) cleanupScreenshots() error {
	v.screenshotMu.Lock()
	defer v.screenshotMu.Unlock()
	if !v.screenshotClosed || v.screenshotCloseErr != nil {
		v.screenshotClosed = true
		if v.screenshotDir != "" {
			v.screenshotCloseErr = os.RemoveAll(v.screenshotDir)
		}
	}
	return v.screenshotCloseErr
}

func (v *Verifier) saveScreenshot(buf []byte) (string, error) {
	v.screenshotMu.Lock()
	defer v.screenshotMu.Unlock()
	if v.screenshotClosed {
		return "", fmt.Errorf("screenshot storage closed")
	}
	if v.screenshotErr != nil {
		return "", v.screenshotErr
	}
	if !v.captureScreenshots || v.screenshotDir == "" {
		return "", fmt.Errorf("screenshot capture disabled")
	}
	path := filepath.Join(v.screenshotDir, "proof-"+rand.Text()+".png")
	if err := privatefs.WriteFile(path, buf); err != nil {
		return "", err
	}
	return path, nil
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
	payload, message, err := InstrumentDialogPayloadContext(ctx, payload)
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
	v.browserOnce.Do(func() {
		v.browserCtx, v.browserCancel, _ = allocopts.NewTabContext(v.allocCtx)
		timer := time.AfterFunc(v.timeout, v.browserCancel)
		defer timer.Stop()
		stop := context.AfterFunc(ctx, v.browserCancel)
		defer stop()
		v.browserErr = chromedp.Run(v.browserCtx)
	})
	if v.browserErr != nil {
		return result, fmt.Errorf("browser startup: %w", v.browserErr)
	}
	tabCtx, tabCancel, diagnostics, setupErr := allocopts.NewIsolatedTabContext(ctx, v.browserCtx, v.timeout)
	if setupErr != nil {
		return result, fmt.Errorf("browser tab: %w", setupErr)
	}
	defer func() {
		tabCancel()
		if err := diagnostics.Err(); err != nil {
			result.Executed = false
			result.Confidence = 0
			result.LoadError = err.Error()
			out = result
			resultErr = errors.Join(resultErr, err)
		}
		if err := diagnostics.CleanupErr(); err != nil {
			result.ConsoleErrors = append(result.ConsoleErrors, err.Error())
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
	stopDialogs := v.installConsoleHandler(tctx, cancel, &consoleErrors, dialogDetected, message)
	defer stopDialogs()
	var rewrite allocopts.RequestRewrite
	if len(rewrites) > 0 {
		rewrite = rewrites[0]
	}
	guard, policy := allocopts.GuardRequests(navURL, cancel, rewrite)
	defer func() {
		guard.Close()
		if err := guard.Err(); err != nil {
			resultErr = errors.Join(resultErr, err)
			result.LoadError = err.Error()
			out = result
		}
	}()
	if err := chromedp.Run(tctx, policy, emulation.SetFocusEmulationEnabled(true)); err != nil {
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
	)
	if err != nil {
		loadErr = err
		result.LoadError = err.Error()
	}

	var interactionScript string
	if message != "" && loadErr == nil && len(dialogDetected) == 0 {
		// Dispatch only to handlers carrying this exact candidate token; no click,
		// form submission, or direct evaluation of submitted payload source.
		encoded, _ := json.Marshal(message)
		interactionScript = fmt.Sprintf(`(() => {
    const token=%s; let actions=[]; let count=0;
    for(const el of document.querySelectorAll('[onfocus],[onmouseover]')) {
      const focus=(el.getAttribute('onfocus')||'').includes(token);
      const hover=(el.getAttribute('onmouseover')||'').includes(token);
      if(!focus && !hover) continue;
      if(count++ >= 16) break;
      if(focus) {if(document.activeElement===el)el.blur();el.focus();actions.push('focus');}
      if(hover) {el.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));actions.push('synthetic mouseover');}
    }
    return [...new Set(actions)].join(', ');
  })()`, encoded)
		if err := chromedp.Run(tctx, chromedp.Evaluate(interactionScript, &result.Interaction)); err != nil {
			loadErr = err
			result.LoadError = err.Error()
		}
	}

	// Check if a dialog was detected
	if loadErr == nil {
		select {
		case d := <-dialogDetected:
			result.Executed = true
			result.DialogType = d.dialogType
			result.DialogMessage = d.message
			result.Confidence = 0.95
		case <-time.After(3 * time.Second):
			// Preserve the late-handler check for applications that create inputs
			// asynchronously, while immediate execution no longer waits this long.
			if interactionScript != "" {
				if err := chromedp.Run(tctx, chromedp.Evaluate(interactionScript, &result.Interaction)); err != nil {
					loadErr = err
					result.LoadError = err.Error()
				}
				select {
				case d := <-dialogDetected:
					result.Executed = true
					result.DialogType = d.dialogType
					result.DialogMessage = d.message
					result.Confidence = .95
				case <-time.After(100 * time.Millisecond):
				case <-tctx.Done():
					loadErr = tctx.Err()
					result.LoadError = loadErr.Error()
				}
			}
		case <-tctx.Done():
			if loadErr == nil {
				loadErr = tctx.Err()
				result.LoadError = loadErr.Error()
			}
		}
	}

	result.ConsoleErrors = v.consoleLoad(&consoleErrors)

	// Capture screenshot if execution was detected
	if v.captureScreenshots && result.Executed && result.Confidence >= 0.9 {
		if v.screenshotErr != nil {
			result.ConsoleErrors = append(result.ConsoleErrors, "screenshot directory: "+v.screenshotErr.Error())
		} else {
			var buf []byte
			if err := chromedp.Run(tctx, chromedp.CaptureScreenshot(&buf)); err == nil {
				if screenshotPath, err := v.saveScreenshot(buf); err == nil {
					result.ScreenshotPath = screenshotPath
				} else {
					result.ConsoleErrors = append(result.ConsoleErrors, "save screenshot: "+err.Error())
				}
			} else {
				result.ConsoleErrors = append(result.ConsoleErrors, "capture screenshot: "+err.Error())
			}
		}
	}

	if policyErr := guard.Err(); policyErr != nil {
		result.Executed = false
		result.Confidence = 0
		result.LoadError = policyErr.Error()
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
func (v *Verifier) installConsoleHandler(ctx context.Context, cancel context.CancelFunc, errors *[]string, detected chan<- dialogInfo, expected ...string) func() {
	return allocopts.ListenDialogs(ctx, cancel, true, func(e *page.EventJavascriptDialogOpening) {
		matched := len(expected) == 0 || expected[0] == "" || e.Message == expected[0]
		if matched && (e.Type == page.DialogTypeAlert || e.Type == page.DialogTypeConfirm || e.Type == page.DialogTypePrompt) {
			select {
			case detected <- dialogInfo{dialogType: string(e.Type), message: e.Message}:
			default:
			}
		}
		v.consoleMu.Lock()
		if len(*errors) < 100 {
			message := e.Message[:min(len(e.Message), 1024)]
			*errors = append(*errors, fmt.Sprintf("JS dialog: %s", message))
		} else if len(*errors) == 100 {
			*errors = append(*errors, "additional browser diagnostics omitted")
		}
		v.consoleMu.Unlock()
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
