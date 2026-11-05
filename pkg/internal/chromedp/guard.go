package chromedp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	ext "github.com/chromedp/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
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
	mu        sync.Mutex
	err       error
	pending   chan *fetch.EventRequestPaused
	auth      chan *fetch.EventAuthRequired
	authTried map[fetch.RequestID]bool
	workers   sync.WaitGroup
	stop      context.CancelFunc
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
	g := &RequestGuard{pending: make(chan *fetch.EventRequestPaused, 128), auth: make(chan *fetch.EventAuthRequired, 128), authTried: make(map[fetch.RequestID]bool)}
	return g, ext.ActionFunc(func(ctx context.Context) error {
		if meter := requestbudget.FromContext(ctx); meter != nil && meter.Browser.Denied() > 0 {
			g.record(requestbudget.ErrBrowser)
			return requestbudget.ErrBrowser
		}
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
					case challenge := <-g.auth:
						proxy, ok := browser.ProxyFromContext(ctx)
						response := &fetch.AuthChallengeResponse{Response: fetch.AuthChallengeResponseResponseCancelAuth}
						g.mu.Lock()
						tried := g.authTried[challenge.RequestID]
						capacity := len(g.authTried) < 128
						if !tried && capacity {
							g.authTried[challenge.RequestID] = true
						}
						g.mu.Unlock()
						if ok && !proxy.Direct() && !tried && capacity && challenge.AuthChallenge != nil && challenge.AuthChallenge.Source == fetch.AuthChallengeSourceProxy && ssrfguard.SameOrigin(proxy.Server(), challenge.AuthChallenge.Origin) {
							response.Response = fetch.AuthChallengeResponseResponseProvideCredentials
							response.Username = proxy.Username()
							response.Password = proxy.Password()
						}
						if err := fetch.ContinueWithAuth(challenge.RequestID, response).Do(ctx); err != nil && ctx.Err() == nil {
							g.fail(fmt.Errorf("browser proxy authentication protocol failed: %w", err), cancel)
							return
						}
						if response.Response != fetch.AuthChallengeResponseResponseProvideCredentials && ctx.Err() == nil {
							g.record(fmt.Errorf("browser authentication rejected or unavailable"))
							if err := page.StopLoading().Do(ctx); err != nil {
								g.mu.Lock()
								g.err = errors.Join(g.err, fmt.Errorf("stop unauthenticated browser page: %w", err))
								g.mu.Unlock()
							}
							cancel()
							return
						}
					case e := <-g.pending:
						if ctx.Err() != nil {
							return
						}
						var err error
						if e.ResourceType == network.ResourceTypeDocument {
							if scopeErr := ssrfguard.CheckNavigation(ctx, e.Request.URL); scopeErr != nil {
								g.record(scopeErr)
								failErr := fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
								stopErr := page.StopLoading().Do(ctx)
								if failErr != nil || stopErr != nil {
									g.mu.Lock()
									g.err = errors.Join(g.err, fmt.Errorf("stop scope-denied browser navigation: %w", errors.Join(failErr, stopErr)))
									g.mu.Unlock()
								}
								cancel()
								return
							}
						}
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
							if meter := requestbudget.FromContext(ctx); meter != nil && !meter.Browser.Take() {
								// Record before cancellation so navigation cannot hide the cause.
								g.record(requestbudget.ErrBrowser)
								// Fail while the session is still attached: detaching a Fetch
								// session can resume paused requests instead of rejecting them.
								failErr := fetch.FailRequest(e.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
								stopErr := page.StopLoading().Do(ctx)
								if failErr != nil || stopErr != nil {
									g.mu.Lock()
									g.err = errors.Join(g.err, fmt.Errorf("stop exhausted browser request: %w", errors.Join(failErr, stopErr)))
									g.mu.Unlock()
								}
								cancel()
								return
							}
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
			if challenge, ok := ev.(*fetch.EventAuthRequired); ok && ctx.Err() == nil {
				select {
				case g.auth <- challenge:
				default:
					g.fail(fmt.Errorf("browser authentication queue capacity exceeded"), cancel)
				}
				return
			}
			e, ok := ev.(*fetch.EventRequestPaused)
			if !ok || ctx.Err() != nil {
				return
			}
			g.enqueue(e, cancel)
		})
		// Only request-stage Fetch events reserve slots. Network events are not
		// counted again; redirect hops receive distinct Fetch request IDs.
		enable := fetch.Enable().WithPatterns([]*fetch.RequestPattern{{URLPattern: "*", RequestStage: fetch.RequestStageRequest}})
		if proxy, ok := browser.ProxyFromContext(ctx); ok && !proxy.Direct() && (proxy.Username() != "" || proxy.Password() != "") {
			enable = enable.WithHandleAuthRequests(true)
		}
		return enable.Do(ctx)
	})
}
