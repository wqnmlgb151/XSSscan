package dom

import (
	"context"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Retain the full async observation budget for pages with executable content.
// Only inert documents with no pending network work may finish early. A quiet
// timer queue alone cannot rule out later rAF, interval or message callbacks.
type pageActivity struct {
	mu      sync.Mutex
	pending map[network.RequestID]bool
	last    time.Time
}

func (a *pageActivity) observe(event any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch e := event.(type) {
	case *network.EventRequestWillBeSent:
		if a.pending == nil {
			a.pending = make(map[network.RequestID]bool)
		}
		a.pending[e.RequestID] = true
	case *network.EventLoadingFinished:
		delete(a.pending, e.RequestID)
	case *network.EventLoadingFailed:
		delete(a.pending, e.RequestID)
	default:
		return
	}
	a.last = time.Now()
}

func (a *pageActivity) wait(ctx context.Context, budget time.Duration) error {
	deadline := time.NewTimer(budget)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return nil
		case <-tick.C:
			var inert bool
			if err := chromedp.Run(ctx, chromedp.Evaluate(`window.__xsscan_hasExecutableContent === false`, &inert)); err != nil {
				return err
			}
			if !inert {
				// The flag is permanent. Further polling cannot shorten the
				// window and only adds CDP traffic to executable pages.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-deadline.C:
					return nil
				}
			}
			a.mu.Lock()
			quiet := len(a.pending) == 0 && time.Since(a.last) >= 80*time.Millisecond
			a.mu.Unlock()
			if inert && quiet {
				return nil
			}
		}
	}
}
