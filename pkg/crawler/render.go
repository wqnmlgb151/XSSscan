package crawler

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/fetch"
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

	// Suppress CDP parse errors (malformed cookies etc.) via a no-op error logger
	logCtx := chromedp.WithErrorf(log.New(io.Discard, "", 0).Printf)
	tabCtx, tabCancel := chromedp.NewContext(allocCtx, logCtx)
	defer tabCancel()

	tctx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	// Parse target host to determine same-origin for request blocking
	targetHost := ""
	if u, err := url.Parse(targetURL); err == nil {
		targetHost = u.Host
	}

	actions := []chromedp.Action{
		network.Enable(),
		// Block cross-origin subrequests (iframes, images, scripts) for safety:
		// prevents loading external malware/redirectors embedded in target pages.
		fetch.Enable().WithHandleAuthRequests(true),
	}
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		chromedp.ListenTarget(ctx, func(ev interface{}) {
			if e, ok := ev.(*fetch.EventRequestPaused); ok {
				go func() {
					reqHost := ""
					if u, err := url.Parse(e.Request.URL); err == nil {
						reqHost = u.Host
					}
					// Only allow same-origin and same-host subrequests
					if reqHost != "" && reqHost != targetHost {
						fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
					} else {
						fetch.ContinueRequest(e.RequestID).Do(ctx)
					}
				}()
			}
		})
		return nil
	}))
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
		chromedp.Sleep(3*time.Second),
		chromedp.OuterHTML("html", &renderedHTML),
	)

	if err := chromedp.Run(tctx, actions...); err != nil {
		return nil, fmt.Errorf("render page: %w", err)
	}

	page := &RenderedPage{}
	page.Forms, _ = extractForms(renderedHTML, targetURL)
	return page, nil
}
