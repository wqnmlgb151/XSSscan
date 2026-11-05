package chromedp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	ext "github.com/chromedp/chromedp"
	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

// NewIsolatedTabContext shares an initialized browser process, but creates a
// private browser context for each check. Explicit newWindow is needed because
// a fresh context has no window in which Chrome can create a tab.
func NewIsolatedTabContext(ctx, parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc, *Diagnostics, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	owner := ext.FromContext(parent)
	if owner == nil || owner.Browser == nil {
		return nil, nil, nil, fmt.Errorf("browser not initialized")
	}
	setup, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	executor := cdp.WithExecutor(setup, owner.Browser)
	id, err := target.CreateBrowserContext().WithDisposeOnDetach(true).Do(executor)
	if err != nil {
		return nil, nil, nil, err
	}
	inherited, _ := parent.Value(diagnosticsKey{}).(*Diagnostics)
	diagnostics := &Diagnostics{parent: inherited}
	dispose := func() {
		cleanup, finish := context.WithTimeout(context.Background(), time.Second)
		defer finish()
		diagnostics.cleanupError(target.DisposeBrowserContext(id).Do(cdp.WithExecutor(cleanup, owner.Browser)))
	}
	tabID, err := target.CreateTarget("about:blank").WithBrowserContextID(id).WithNewWindow(true).Do(executor)
	if err != nil {
		dispose()
		return nil, nil, nil, errors.Join(err, diagnostics.Err(), diagnostics.CleanupErr())
	}
	lifetime, endLifetime := context.WithCancel(parent)
	if meter := requestbudget.FromContext(ctx); meter != nil {
		lifetime = requestbudget.WithMeter(lifetime, meter)
	}
	lifetime = ssrfguard.InheritURLFilter(lifetime, ctx)
	tab, closeTab, _ := NewTabContext(lifetime, ext.WithTargetID(tabID))
	stopCaller := context.AfterFunc(ctx, endLifetime)
	var once sync.Once
	return context.WithValue(tab, diagnosticsKey{}, diagnostics), func() { once.Do(func() { stopCaller(); closeTab(); endLifetime(); dispose() }) }, diagnostics, nil
}
