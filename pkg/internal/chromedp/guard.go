package chromedp

import (
	"context"
	"fmt"
	"sync"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	ext "github.com/chromedp/chromedp"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// RequestRewrite can override a permitted request, for authenticated replay.
type RequestRewrite func(*fetch.EventRequestPaused) *fetch.ContinueRequestParams

// RequestGuard confines intercepted HTTP requests to one origin. Chrome owns
// DNS and sockets: this is a scope check, not the Go transport's pinned dial.
type RequestGuard struct {
	mu      sync.Mutex
	err     error
	pending chan *fetch.EventRequestPaused
	workers sync.WaitGroup
}

func (g *RequestGuard) enqueue(e *fetch.EventRequestPaused, cancel context.CancelFunc) {
	select {
	case g.pending <- e:
	default:
		g.fail(fmt.Errorf("browser request queue capacity exceeded"), cancel)
	}
}

// Err returns the first protocol or queue failure, if any.
func (g *RequestGuard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

func (g *RequestGuard) fail(err error, cancel context.CancelFunc) {
	g.mu.Lock()
	if g.err == nil {
		g.err = err
	}
	g.mu.Unlock()
	cancel()
}

// GuardRequests uses bounded workers. CDP listeners never perform synchronous
// protocol calls. Saturation cancels the tab instead of leaving requests paused.
func GuardRequests(origin string, cancel context.CancelFunc, rewrite RequestRewrite) (*RequestGuard, ext.Action) {
	g := &RequestGuard{pending: make(chan *fetch.EventRequestPaused, 128)}
	return g, ext.ActionFunc(func(ctx context.Context) error {
		if err := ssrfguard.IsURLTargetAllowedContext(ctx, origin); err != nil {
			return err
		}
		g.workers.Add(8)
		for i := 0; i < 8; i++ {
			go func() {
				defer g.workers.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case e := <-g.pending:
						var err error
						if !ssrfguard.SameOrigin(origin, e.Request.URL) {
							err = fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
						} else if err = ssrfguard.IsURLTargetAllowedContext(ctx, e.Request.URL); err == nil {
							continuation := fetch.ContinueRequest(e.RequestID)
							if rewrite != nil {
								continuation = rewrite(e)
							}
							err = continuation.Do(ctx)
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
