package chromedp

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	ext "github.com/chromedp/chromedp"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// RequestRewrite can override a permitted request, for authenticated replay.
type RequestRewrite func(*fetch.EventRequestPaused) *fetch.ContinueRequestParams

// NavigationPolicyError distinguishes a blocked top-level navigation from
// blocked third-party subresources. The original URLs remain available to callers.
type NavigationPolicyError struct {
	Origin     string
	RequestURL string
}

func (e *NavigationPolicyError) Error() string {
	return fmt.Sprintf("browser main-document navigation blocked by same-origin policy: %s -> %s; configure the final target URL explicitly", originLabel(e.Origin), originLabel(e.RequestURL))
}

func originLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// RequestGuard confines intercepted HTTP requests to one origin. Chrome owns
// DNS and sockets: this is a scope check, not the Go transport's pinned dial.
type RequestGuard struct {
	mu      sync.Mutex
	err     error
	pending chan *fetch.EventRequestPaused
	workers sync.WaitGroup
	stop    context.CancelFunc
}

// Close stops request workers and waits for them. Call after the policy action
// returns; it never closes the listener's input channel.
func (g *RequestGuard) Close() {
	if g.stop != nil {
		g.stop()
	}
	g.workers.Wait()
}

func (g *RequestGuard) enqueue(e *fetch.EventRequestPaused, cancel context.CancelFunc) {
	select {
	case g.pending <- e:
	default:
		g.fail(fmt.Errorf("browser request queue capacity exceeded"), cancel)
	}
}

// Err returns the first main-navigation, protocol or queue failure, if any.
func (g *RequestGuard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

func (g *RequestGuard) fail(err error, cancel context.CancelFunc) {
	g.record(err)
	cancel()
}

func (g *RequestGuard) record(err error) {
	g.mu.Lock()
	if g.err == nil {
		g.err = err
	}
	g.mu.Unlock()
}

// GuardRequests uses bounded workers. CDP listeners never perform synchronous
// protocol calls. Saturation cancels the tab instead of leaving requests paused.
func GuardRequests(origin string, cancel context.CancelFunc, rewrite RequestRewrite) (*RequestGuard, ext.Action) {
	g := &RequestGuard{pending: make(chan *fetch.EventRequestPaused, 128)}
	return g, ext.ActionFunc(func(ctx context.Context) error {
		if err := ssrfguard.IsURLTargetAllowedContext(ctx, origin); err != nil {
			return err
		}
		tree, err := page.GetFrameTree().Do(ctx)
		if err != nil {
			return fmt.Errorf("identify browser main frame: %w", err)
		}
		mainFrame := tree.Frame.ID
		ctx, g.stop = context.WithCancel(ctx)
		g.workers.Add(8)
		for i := 0; i < 8; i++ {
			go func() {
				defer g.workers.Done()
				defer func() {
					if value := recover(); value != nil {
						g.fail(fmt.Errorf("browser request worker panic: %v", value), cancel)
					}
				}()
				for {
					select {
					case <-ctx.Done():
						return
					case e := <-g.pending:
						var err error
						if !ssrfguard.SameOrigin(origin, e.Request.URL) {
							mainNavigation := e.ResourceType == network.ResourceTypeDocument && e.FrameID == mainFrame
							if mainNavigation {
								// Record before FailRequest: Navigate can return as soon as
								// Chrome receives the failure, before this worker resumes.
								g.record(&NavigationPolicyError{Origin: origin, RequestURL: e.Request.URL})
							}
							err = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
							if mainNavigation {
								cancel()
								return
							}
						} else if err = ssrfguard.IsURLTargetAllowedContext(ctx, e.Request.URL); err == nil {
							continuation := fetch.ContinueRequest(e.RequestID)
							if rewrite != nil {
								continuation = rewrite(e)
							}
							if continuation == nil {
								err = fmt.Errorf("request rewrite returned no continuation")
							} else {
								err = continuation.Do(ctx)
							}
						}
						if err != nil && ctx.Err() == nil {
							g.fail(fmt.Errorf("browser request policy: %w", err), cancel)
							return
						}
					}
				}
			}()
		}
		ext.ListenTarget(ctx, func(ev interface{}) {
			e, ok := ev.(*fetch.EventRequestPaused)
			if !ok || ctx.Err() != nil {
				return
			}
			g.enqueue(e, cancel)
		})
		return fetch.Enable().Do(ctx)
	})
}
