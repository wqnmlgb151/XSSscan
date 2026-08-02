package scanner

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestNewThrottle(t *testing.T) {
	th := NewThrottle(50, 100, false)
	if th == nil {
		t.Fatal("NewThrottle returned nil")
	}
	if th.defaultRPS != 50 {
		t.Errorf("Expected defaultRPS=50, got %v", th.defaultRPS)
	}
	if th.burst != 100 {
		t.Errorf("Expected burst=100, got %d", th.burst)
	}
	if th.adaptive {
		t.Error("Expected adaptive=false")
	}
}

func TestNewThrottleAdaptive(t *testing.T) {
	th := NewThrottle(50, 100, true)
	if !th.adaptive {
		t.Error("Expected adaptive=true")
	}
}

func TestThrottleWait(t *testing.T) {
	th := NewThrottle(100, 200, false)
	ctx := context.Background()
	err := th.Wait(ctx, "example.com")
	if err != nil {
		t.Errorf("Wait returned error: %v", err)
	}
}

func TestReport429NonAdaptive(t *testing.T) {
	th := NewThrottle(50, 100, false)
	limit := th.CurrentLimit()
	th.Report429Global()
	if th.CurrentLimit() != limit {
		t.Error("Non-adaptive throttle should not change limit on 429")
	}
}

func TestReport429Adaptive(t *testing.T) {
	th := NewThrottle(50, 100, true)
	th.Report429Global()
	newLimit := th.CurrentLimit()
	if newLimit != 25 {
		t.Errorf("Expected limit=25 after 429 (half of 50), got %v", newLimit)
	}
}

func TestReport429Floor(t *testing.T) {
	th := NewThrottle(2, 4, true)
	th.Report429Global()
	limit := th.CurrentLimit()
	if limit != 1 {
		t.Errorf("Expected limit=1 (floor), got %v", limit)
	}
	// One more 429 should stay at 1
	th.Report429Global()
	if th.CurrentLimit() != 1 {
		t.Error("Limit should not go below 1")
	}
}

func TestReport429PerHost(t *testing.T) {
	th := NewThrottle(100, 200, true)
	host := "example.com"
	th.Report429Host(host)
	// Global limit should be unchanged
	if th.CurrentLimit() != 100 {
		t.Errorf("Global limit should remain 100, got %v", th.CurrentLimit())
	}
	// Per-host limiter should be created with halved rate
	th.mu.Lock()
	l, ok := th.hostLimiters[host]
	th.mu.Unlock()
	if !ok {
		t.Fatal("Expected per-host limiter to be created")
	}
	if l.Limit() != 25 {
		t.Errorf("Expected per-host limit=25, got %v", l.Limit())
	}
}

func TestReport429PerHostIsolation(t *testing.T) {
	th := NewThrottle(100, 200, true)
	// 429 from host-a should not affect host-b
	th.Report429Host("host-a.com")
	th.mu.Lock()
	lB, ok := th.hostLimiters["host-b.com"]
	th.mu.Unlock()
	if ok && lB.Limit() != 50 { // default per-host is 100/2=50
		t.Errorf("host-b limiter should be unaffected, got %v", lB.Limit())
	}
}

func TestReportSuccessNonAdaptive(t *testing.T) {
	th := NewThrottle(50, 100, false)
	limit := th.CurrentLimit()
	th.ReportSuccess()
	if th.CurrentLimit() != limit {
		t.Error("Non-adaptive throttle should not change limit on success")
	}
}

func TestReportSuccessRecovery(t *testing.T) {
	th := NewThrottle(100, 200, true)
	// Simulate 429 to drop limit
	th.Report429Global() // 100 → 50
	th.Report429Global() // 50 → 25

	// Now recover
	th.ReportSuccess() // 25 * 1.1 = 27.5
	expected := rate.Limit(27.5)
	if th.CurrentLimit() != expected {
		t.Errorf("Expected limit=%v after recovery, got %v", expected, th.CurrentLimit())
	}
}

func TestReportSuccessCeiling(t *testing.T) {
	th := NewThrottle(10, 20, true)
	// Try to recover beyond default — should cap at defaultRPS
	for i := 0; i < 100; i++ {
		th.ReportSuccess()
	}
	if th.CurrentLimit() > 10 {
		t.Errorf("Limit should not exceed defaultRPS (10), got %v", th.CurrentLimit())
	}
}

func TestCurrentLimit(t *testing.T) {
	th := NewThrottle(42, 84, false)
	if th.CurrentLimit() != 42 {
		t.Errorf("Expected current limit=42, got %v", th.CurrentLimit())
	}
}

func TestThrottleMultipleHosts(t *testing.T) {
	th := NewThrottle(100, 200, false)
	ctx := context.Background()
	for _, host := range []string{"a.com", "b.com", "c.com"} {
		if err := th.Wait(ctx, host); err != nil {
			t.Errorf("Wait for %s returned error: %v", host, err)
		}
	}
	if len(th.hostLimiters) != 3 {
		t.Errorf("Expected 3 host limiters, got %d", len(th.hostLimiters))
	}
}

func TestThrottleContextCancel(t *testing.T) {
	th := NewThrottle(1, 1, false) // Very slow rate
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	err := th.Wait(ctx, "example.com")
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

func TestAdaptiveRateE2E(t *testing.T) {
	th := NewThrottle(100, 200, true)

	// Simulate some successful requests
	for i := 0; i < 5; i++ {
		th.ReportSuccess()
	}

	// Simulate 429
	th.Report429Global()
	after429 := th.CurrentLimit()
	if after429 >= 100 {
		t.Errorf("Limit should decrease after 429, got %v", after429)
	}

	// Recover
	for i := 0; i < 50; i++ {
		th.ReportSuccess()
	}
	recovered := th.CurrentLimit()
	if recovered <= after429 {
		t.Errorf("Limit should recover after successes, got %v (was %v)", recovered, after429)
	}
	if recovered > 100 {
		t.Errorf("Limit should not exceed default, got %v", recovered)
	}
}

func TestThrottleWaitWithJitter(t *testing.T) {
	th := NewThrottle(1000, 2000, false) // High rate so jitter is the main delay
	ctx := context.Background()
	start := time.Now()
	err := th.Wait(ctx, "example.com")
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("Wait returned error: %v", err)
	}
	// Jitter is 0-50ms, should complete well under 200ms
	if elapsed > 200*time.Millisecond {
		t.Errorf("Wait took too long: %v", elapsed)
	}
}
