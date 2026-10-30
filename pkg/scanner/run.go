package scanner

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
)

type countedTransport struct {
	base  http.RoundTripper
	count *int64
}

func (t countedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(t.count, 1)
	if trace := traceFrom(req.Context()); trace != nil {
		return trace.roundTrip(req, t.base)
	}
	return t.base.RoundTrip(req)
}

// Run serializes calls on one Engine; waiting callers can cancel. Configure
// generators before calling Run. Session cookies persist by normal jar rules;
// target-specific counters, CSRF, WAF and adaptive state do not.
func (e *Engine) Run(ctx context.Context, target model.Target) (*model.ScanResult, error) {
	select {
	case e.runGate <- struct{}{}:
		defer func() { <-e.runGate }()
	case <-ctx.Done():
		return &model.ScanResult{Target: target.URL, Stats: model.ScanStats{Status: model.ScanCanceled, Issues: []model.ScanIssue{{Target: target.URL, Stage: "queue", Message: ctx.Err().Error()}}}}, ctx.Err()
	}
	start := time.Now()
	e.observations.reset()
	atomic.StoreInt64(&e.payloadsSent, 0)
	atomic.StoreInt64(&e.requestsSent, 0)
	atomic.StoreInt64(&e.succeeded, 0)
	atomic.StoreInt64(&e.errors, 0)
	e.probeFiltered = 0
	atomic.StoreInt32(&e.wafLogged, 0)
	e.wafTracker = &WAFTracker{}
	e.throttle = NewThrottle(e.config.RateLimit, e.config.RateBurst, e.config.AdaptiveRate)
	e.csrfToken.Store("")
	e.csrfFieldName.Store(e.config.CSRFFieldName)
	var mutator *payload.Mutator
	if e.config.WAFBypass {
		mutator = payload.NewMutator()
	}
	e.mutator.Store(mutator)
	e.issueMu.Lock()
	e.runIssues = nil
	e.runCoverage = nil
	e.firstError = nil
	e.runTarget = target.URL
	e.issueMu.Unlock()
	result, err := e.run(ctx, target)
	if result == nil {
		result = &model.ScanResult{Target: target.URL}
	}
	if err != nil {
		e.recordRunError("analysis", err)
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	e.issueMu.Lock()
	result.Stats.Issues = append([]model.ScanIssue(nil), e.runIssues...)
	result.Stats.Coverage = append([]model.CheckCoverage(nil), e.runCoverage...)
	if err == nil && e.firstError != nil {
		err = fmt.Errorf("scan incomplete: %w", e.firstError)
	}
	e.issueMu.Unlock()
	result.Stats.StartTime = start.UnixMilli()
	result.Stats.EndTime = time.Now().UnixMilli()
	result.Stats.Duration = time.Since(start).Milliseconds()
	result.Stats.PayloadsSent = int(atomic.LoadInt64(&e.payloadsSent))
	result.Stats.RequestsSent = int(atomic.LoadInt64(&e.requestsSent))
	result.Stats.Errors = int(atomic.LoadInt64(&e.errors))
	result.Stats.ProbeFiltered = e.probeFiltered
	result.Stats.WAF = e.wafTracker.Result()
	result.Stats.Status = model.ScanCompleted
	if err != nil {
		result.Stats.Status = model.ScanFailed
		if atomic.LoadInt64(&e.succeeded) > 0 || len(result.Findings) > 0 {
			result.Stats.Status = model.ScanPartial
		}
		if ctx.Err() != nil {
			result.Stats.Status = model.ScanCanceled
		}
		if len(result.Stats.Issues) == 0 {
			result.Stats.Issues = []model.ScanIssue{{Target: target.URL, Stage: "scan", Message: err.Error()}}
		}
	}
	return result, err
}

func (e *Engine) recordCoverage(coverage model.CheckCoverage) {
	e.issueMu.Lock()
	coverage.Target = e.runTarget
	e.runCoverage = append(e.runCoverage, coverage)
	e.issueMu.Unlock()
}

func (e *Engine) recordRunError(stage string, err error) {
	if err == nil {
		return
	}
	atomic.AddInt64(&e.errors, 1)
	e.issueMu.Lock()
	defer e.issueMu.Unlock()
	if e.firstError == nil {
		e.firstError = err
	}
	for _, issue := range e.runIssues {
		if issue.Stage == stage && issue.Message == err.Error() {
			return
		}
	}
	if len(e.runIssues) < 100 {
		e.runIssues = append(e.runIssues, model.ScanIssue{Target: e.runTarget, Stage: stage, Message: err.Error()})
	}
}
