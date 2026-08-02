package scanner

import (
	"sync"
	"sync/atomic"

	"github.com/xsscan/xsscan/pkg/model"
)


// WAFTracker accumulates WAF detection state across concurrent scan workers.
// All methods are safe for concurrent use.
type WAFTracker struct {
	detected int64
	nameOnce sync.Once
	name     string
	bypassed int64
}

// Report records a WAF detection result. The first non-empty name wins.
func (t *WAFTracker) Report(detected bool, name string, bypassed bool) {
	if !detected {
		return
	}
	atomic.StoreInt64(&t.detected, 1)
	if name != "" {
		t.nameOnce.Do(func() { t.name = name })
	}
	if bypassed {
		atomic.StoreInt64(&t.bypassed, 1)
	}
}

// Result returns the accumulated WAF info, or nil if no WAF was detected.
func (t *WAFTracker) Result() *model.WAFInfo {
	if atomic.LoadInt64(&t.detected) == 0 {
		return nil
	}
	return &model.WAFInfo{
		Name:     t.name,
		Bypassed: atomic.LoadInt64(&t.bypassed) == 1,
	}
}

// Detected returns true if any WAF has been reported.
func (t *WAFTracker) Detected() bool {
	return atomic.LoadInt64(&t.detected) == 1
}
