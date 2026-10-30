package chromedp

import (
	"context"
	"github.com/chromedp/cdproto/page"
	ext "github.com/chromedp/chromedp"
)

// ListenDialogs keeps protocol work off the CDP listener and bounds pending
// dismissals. The observer must return promptly. Stop joins the single worker.
func ListenDialogs(ctx context.Context, cancel context.CancelFunc, accept bool, observe func(*page.EventJavascriptDialogOpening)) func() {
	workerCtx, stop := context.WithCancel(ctx)
	pending := make(chan struct{}, 8)
	done := make(chan struct{})
	fail := func(message string) {
		if d, ok := ctx.Value(diagnosticsKey{}).(*Diagnostics); ok {
			d.errorf("%s", message)
		}
		cancel()
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-pending:
				if err := ext.Run(workerCtx, page.HandleJavaScriptDialog(accept)); err != nil && workerCtx.Err() == nil {
					fail("dismiss JavaScript dialog: " + err.Error())
					return
				}
			}
		}
	}()
	ext.ListenTarget(workerCtx, func(event interface{}) {
		dialog, ok := event.(*page.EventJavascriptDialogOpening)
		if !ok || workerCtx.Err() != nil {
			return
		}
		if observe != nil {
			observe(dialog)
		}
		select {
		case pending <- struct{}{}:
		default:
			fail("browser dialog queue capacity exceeded")
		}
	})
	return func() { stop(); <-done }
}
