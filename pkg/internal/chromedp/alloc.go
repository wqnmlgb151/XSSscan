// Package chromedp provides shared headless Chrome allocator configuration.
//
// All three browser-dependent packages (dom, execverify, crawler) need the
// same hardening options. Centralizing them here prevents drift and fixes
// the option-ordering bug where custom options were silently overridden by
// chromedp defaults (chromedp applies options in order, later wins).
//
// Chrome binary detection lives in pkg/browser (importable from cmd/, which
// cannot import this package due to the internal rule).
package chromedp

import (
	"context"

	ext "github.com/chromedp/chromedp"

	"github.com/xsscan/xsscan/pkg/browser"
)

// StandardHeadlessOptions are the hardening options shared by all call sites.
var StandardHeadlessOptions = []ext.ExecAllocatorOption{
	ext.NoFirstRun,
	ext.NoDefaultBrowserCheck,
	ext.Headless,
	ext.DisableGPU,
	ext.Flag("no-sandbox", false),
	ext.Flag("ignore-certificate-errors", false),
	ext.WindowSize(1280, 800),
}

// AllocatorOptions returns the full option list with defaults FIRST and
// custom options LAST, so custom options take effect (later wins).
func AllocatorOptions(custom ...ext.ExecAllocatorOption) []ext.ExecAllocatorOption {
	opts := append([]ext.ExecAllocatorOption(nil), ext.DefaultExecAllocatorOptions[:]...)
	return append(opts, custom...)
}

// NewExecAllocator creates an allocator context with standard options plus
// caller options, followed by the explicit browser compatibility settings.
// The CLI settings take precedence over caller options. When ChromePath is set, the
// binary location is pinned via ExecPath.
func NewExecAllocator(ctx context.Context, custom ...ext.ExecAllocatorOption) (context.Context, context.CancelFunc) {
	custom = append(custom, ext.Flag("no-sandbox", browser.NoSandbox), ext.Flag("ignore-certificate-errors", browser.IgnoreCertErrors))
	if browser.ChromePath != "" {
		custom = append(custom, ext.ExecPath(browser.ChromePath))
	} else if found, err := browser.FindChrome(); err == nil {
		// Pin the detected binary so the pre-flight warning and the actual
		// launch always agree (chromedp's own lookup may differ).
		custom = append(custom, ext.ExecPath(found))
	}
	return ext.NewExecAllocator(ctx, AllocatorOptions(custom...)...)
}
