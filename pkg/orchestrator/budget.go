package orchestrator

import (
	"errors"
	"net/http"
	"sync/atomic"
)

var ErrRequestBudget = errors.New("HTTP request budget exhausted")

// BudgetTransport limits actual Go HTTP attempts, including redirects and
// retries. Browser network accounting remains a separate U5 concern.
type BudgetTransport struct {
	Base  http.RoundTripper
	Max   int64
	count atomic.Int64
}

func (b *BudgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	for {
		n := b.count.Load()
		if b.Max > 0 && n >= b.Max {
			return nil, ErrRequestBudget
		}
		if b.count.CompareAndSwap(n, n+1) {
			break
		}
	}
	base := b.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func (b *BudgetTransport) Count() int64 { return b.count.Load() }
