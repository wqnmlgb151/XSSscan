package chromedp

import (
	"context"
	"fmt"
	"log"
	"sync"

	ext "github.com/chromedp/chromedp"
)

// Diagnostics retains protocol decoding failures independently of navigation.
// A completed page load cannot compensate for missing browser events.
type Diagnostics struct {
	mu  sync.Mutex
	err error
}

func (d *Diagnostics) errorf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	log.Print(message)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err == nil {
		d.err = fmt.Errorf("browser protocol processing failed: %s", message)
	}
}

// Err returns the first chromedp error. WithErrorf is for browser transport and
// event processing errors; target JavaScript exceptions arrive as CDP events.
func (d *Diagnostics) Err() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// NewTabContext supplies the same error contract to rendering and detectors.
func NewTabContext(parent context.Context) (context.Context, context.CancelFunc, *Diagnostics) {
	diagnostics := &Diagnostics{}
	ctx, cancel := ext.NewContext(parent, ext.WithErrorf(diagnostics.errorf))
	return ctx, cancel, diagnostics
}
