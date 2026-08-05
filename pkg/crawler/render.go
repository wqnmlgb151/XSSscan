package crawler

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// RenderedPage holds the forms extracted from a JS-rendered page.
type RenderedPage struct {
	Forms []FormInfo
}

// renderTimeout is the default timeout for JS page rendering.
const renderTimeout = 15 * time.Second

// RenderPage uses headless Chrome to render a JS-heavy page, then extracts
// forms from the fully-rendered DOM. Headers are forwarded so authenticated
// SPA pages are rendered correctly (JWT, OAuth, custom headers).
func RenderPage(ctx context.Context, targetURL string, headers map[string]string, timeout time.Duration) (*RenderedPage, error) {
	if timeout <= 0 {
		timeout = renderTimeout
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.IgnoreCertErrors,
		chromedp.WindowSize(1280, 800),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	tctx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	actions := []chromedp.Action{network.Enable()}
	if len(headers) > 0 {
		h := make(network.Headers)
		for k, v := range headers {
			h[k] = v
		}
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			return network.SetExtraHTTPHeaders(h).Do(ctx)
		}))
	}

	var renderedHTML string
	actions = append(actions,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(2*time.Second), // wait for async JS rendering
		chromedp.OuterHTML("html", &renderedHTML),
	)

	if err := chromedp.Run(tctx, actions...); err != nil {
		return nil, fmt.Errorf("render page: %w", err)
	}

	page := &RenderedPage{}
	page.Forms, _ = extractForms(renderedHTML, targetURL)
	return page, nil
}
