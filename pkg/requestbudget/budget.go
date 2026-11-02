// Package requestbudget accounts admitted request attempts, not wire bytes or responses.
package requestbudget

import (
	"context"
	"errors"
	"sync/atomic"
)

var ErrHTTP = errors.New("HTTP request budget exhausted")
var ErrBrowser = errors.New("browser request budget exhausted")

// Counter is shared by concurrent tasks. Limits are immutable after construction.
// A reservation counts even if the subsequent transport/protocol operation fails.
type Counter struct {
	limit  int64
	count  atomic.Int64
	denied atomic.Int64
}

func NewCounter(limit int64) *Counter { return &Counter{limit: limit} }
func (c *Counter) Take() bool {
	for {
		n := c.count.Load()
		if c.limit > 0 && n >= c.limit {
			c.denied.Add(1)
			return false
		}
		if c.count.CompareAndSwap(n, n+1) {
			return true
		}
	}
}
func (c *Counter) Count() int64  { return c.count.Load() }
func (c *Counter) Denied() int64 { return c.denied.Load() }

// Meter keeps the legacy Go HTTP and independent browser budgets separate.
// One instance is scoped to a batch, never a process-global mutable variable.
type Meter struct{ HTTP, Browser *Counter }

func New(httpLimit, browserLimit int64) *Meter {
	return &Meter{HTTP: NewCounter(httpLimit), Browser: NewCounter(browserLimit)}
}

type key struct{}

func WithMeter(ctx context.Context, meter *Meter) context.Context {
	return context.WithValue(ctx, key{}, meter)
}
func FromContext(ctx context.Context) *Meter { meter, _ := ctx.Value(key{}).(*Meter); return meter }
