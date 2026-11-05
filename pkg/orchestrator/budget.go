package orchestrator

import (
	"net/http"
	"sync"

	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
)

var ErrRequestBudget = requestbudget.ErrHTTP

// BudgetTransport limits actual Go HTTP attempts, including redirects and
// retries. The optional shared meter preserves independent browser accounting.
type BudgetTransport struct {
	Base    http.RoundTripper
	Max     int64
	Meter   *requestbudget.Meter
	once    sync.Once
	counter *requestbudget.Counter
}

func (b *BudgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if !b.getCounter().Take() {
		return nil, ErrRequestBudget
	}
	base := b.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func (b *BudgetTransport) getCounter() *requestbudget.Counter {
	b.once.Do(func() {
		b.counter = requestbudget.NewCounter(b.Max)
		if b.Meter != nil {
			b.counter = b.Meter.HTTP
		}
	})
	return b.counter
}
func (b *BudgetTransport) Count() int64 { return b.getCounter().Count() }
