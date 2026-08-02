package scanner

import (
	"context"
	"math"
	"sync"

	"golang.org/x/time/rate"
)

// Throttle provides token-bucket rate limiting per host with optional adaptive mode.
type Throttle struct {
	limiter      *rate.Limiter
	mu           sync.Mutex
	hostLimiters map[string]*rate.Limiter
	defaultRPS   rate.Limit
	burst        int
	adaptive     bool
}

// NewThrottle creates a new throttle with global RPS and burst.
// When adaptive is true, the rate limit auto-adjusts on 429 responses.
func NewThrottle(rps int, burst int, adaptive bool) *Throttle {
	return &Throttle{
		limiter:      rate.NewLimiter(rate.Limit(rps), burst),
		hostLimiters: make(map[string]*rate.Limiter),
		defaultRPS:   rate.Limit(rps),
		burst:        burst,
		adaptive:     adaptive,
	}
}

// Wait blocks until a request is allowed for the given host.
func (t *Throttle) Wait(ctx context.Context, host string) error {
	t.mu.Lock()
	l, ok := t.hostLimiters[host]
	if !ok {
		hostRPS := t.defaultRPS / 2
		if hostRPS < 1 {
			hostRPS = 1
		}
		l = rate.NewLimiter(hostRPS, t.burst/2+1)
		t.hostLimiters[host] = l
	}
	t.mu.Unlock()
	if err := t.limiter.Wait(ctx); err != nil {
		return err
	}
	return l.Wait(ctx)
}

// newHostLimiter creates a fresh per-host limiter at half the default rate.
// Shared by Wait and Report429Host so they never diverge on initial rate.
func (t *Throttle) newHostLimiter() *rate.Limiter {
	hostRPS := t.defaultRPS / 2
	if hostRPS < 1 {
		hostRPS = 1
	}
	return rate.NewLimiter(hostRPS, t.burst/2+1)
}

// Report429Host halves the per-host rate limit (floor: 1 rps).
// Per-host throttling ensures one aggressive target doesn't slow down all others.
func (t *Throttle) Report429Host(host string) {
	if !t.adaptive {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.hostLimiters[host]
	if !ok {
		l = t.newHostLimiter()
		t.hostLimiters[host] = l
	}
	t.halveLimit(l)
}

// Report429Global halves the global rate limit.
func (t *Throttle) Report429Global() {
	if !t.adaptive {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.halveLimit(t.limiter)
}

// ReportSuccessHost recovers the per-host rate limit toward the default.
func (t *Throttle) ReportSuccessHost(host string) {
	if !t.adaptive {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.hostLimiters[host]; ok {
		t.recoverLimit(l)
	}
}

// ReportSuccess recovers the global rate limit toward the default.
func (t *Throttle) ReportSuccess() {
	if !t.adaptive {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recoverLimit(t.limiter)
}

// halveLimit halves a limiter's rate, flooring at 1.
func (t *Throttle) halveLimit(l *rate.Limiter) {
	newLimit := l.Limit() / 2
	if newLimit < 1 {
		newLimit = 1
	}
	l.SetLimit(newLimit)
}

// recoverLimit increases a limiter's rate by 10% toward defaultRPS, rounding to 0.1.
func (t *Throttle) recoverLimit(l *rate.Limiter) {
	newLimit := l.Limit() * 1.1
	if newLimit > t.defaultRPS {
		newLimit = t.defaultRPS
	}
	l.SetLimit(rate.Limit(math.Round(float64(newLimit)*10) / 10))
}

// CurrentLimit returns the current global rate limit (for testing/observability).
func (t *Throttle) CurrentLimit() rate.Limit {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.limiter.Limit()
}

