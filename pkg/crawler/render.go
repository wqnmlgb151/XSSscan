package crawler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	allocopts "github.com/xsscan/xsscan/pkg/internal/chromedp"
)

// RenderedPage holds the forms extracted from a JS-rendered page.
type RenderedPage struct {
	Forms []FormInfo
}

// renderTimeout is the default timeout for JS page rendering.
const renderTimeout = 15 * time.Second

func renderTimeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return renderTimeout
	}
	return timeout
}

func toNetworkHeaders(headers map[string]string) network.Headers {
	h := make(network.Headers, len(headers))
	for k, v := range headers {
		h[k] = v
	}
	return h
}

// RenderPage uses headless Chrome to render a JS-heavy page, then extracts
// forms from the fully-rendered DOM. Headers are forwarded so authenticated
// SPA pages are rendered correctly (JWT, OAuth, custom headers).
func RenderPage(ctx context.Context, targetURL string, headers map[string]string, timeout time.Duration) (result *RenderedPage, resultErr error) {
	timeout = renderTimeoutOrDefault(timeout)

	allocCtx, allocCancel := allocopts.NewExecAllocator(ctx, allocopts.StandardHeadlessOptions...)
	defer allocCancel()

	tabCtx, tabCancel, diagnostics := allocopts.NewTabContext(allocCtx)
	defer tabCancel()
	defer func() {
		if err := diagnostics.Err(); err != nil {
			result = nil
			resultErr = errors.Join(resultErr, err)
		}
	}()

	tctx, cancel := context.WithTimeout(tabCtx, timeout)
	defer cancel()

	guard, policy := allocopts.GuardRequests(targetURL, cancel, nil)
	defer guard.Close()
	actions := []chromedp.Action{network.Enable(), policy}
	if len(headers) > 0 {
		h := toNetworkHeaders(headers)
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
		if policyErr := guard.Err(); policyErr != nil {
			return nil, policyErr
		}
		return nil, fmt.Errorf("render page: %w", err)
	}

	page := &RenderedPage{}
	page.Forms, _ = extractForms(renderedHTML, targetURL)
	return page, nil
}
