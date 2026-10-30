package chromedp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	ext "github.com/chromedp/chromedp"
)

// Diagnostics retains protocol decoding failures independently of navigation.
// A completed page load cannot compensate for missing browser events.
type Diagnostics struct {
	mu      sync.Mutex
	err     error
	parent  *Diagnostics
	cleanup error
}

type diagnosticsKey struct{}

func (d *Diagnostics) errorf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
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
	err := d.err
	d.mu.Unlock()
	if d.parent != nil {
		err = errors.Join(err, d.parent.Err())
	}
	return err
}

func (d *Diagnostics) cleanupError(err error) {
	if err == nil {
		return
	}
	d.mu.Lock()
	d.cleanup = errors.Join(d.cleanup, &CleanupError{Cause: err})
	d.mu.Unlock()
}

// CleanupError affects resource ownership, not evidence already observed.
type CleanupError struct{ Cause error }

func (e *CleanupError) Error() string    { return "browser resource cleanup failed: " + e.Cause.Error() }
func (e *CleanupError) Unwrap() error    { return e.Cause }
func (d *Diagnostics) CleanupErr() error { d.mu.Lock(); defer d.mu.Unlock(); return d.cleanup }

// OnlyCleanupErrors rejects mixed transport/protocol failures conservatively.
func OnlyCleanupErrors(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*CleanupError); ok {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !OnlyCleanupErrors(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return OnlyCleanupErrors(wrapped.Unwrap())
	}
	return false
}

// NewTabContext supplies the same error contract to rendering and detectors.
func NewTabContext(parent context.Context, options ...ext.ContextOption) (context.Context, context.CancelFunc, *Diagnostics) {
	diagnostics := &Diagnostics{}
	if owner := ext.FromContext(parent); owner != nil && owner.Browser != nil {
		// Error callbacks belong to the browser transport, not individual tabs.
		// Replacing them on an already allocated browser panics in chromedp.
		if inherited, ok := parent.Value(diagnosticsKey{}).(*Diagnostics); ok {
			diagnostics = inherited
		}
	} else {
		options = append(options, ext.WithErrorf(diagnostics.errorf))
	}
	ctx, cancel := ext.NewContext(parent, options...)
	return context.WithValue(ctx, diagnosticsKey{}, diagnostics), cancel, diagnostics
}
