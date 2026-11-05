package scanner

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"go.uber.org/zap"
)

func withAllowPrivate(t *testing.T) {
	t.Helper()

}

func newStrategyTestEngine(preset string, strategy string) *Engine {
	cfg := Config{
		Concurrency:     4,
		RateLimit:       1000,
		RateBurst:       2000,
		RequestTimeout:  5 * time.Second,
		MaxPayloads:     8,
		ConfidenceMin:   0.60,
		ConfidenceSet:   true,
		Strategy:        strategy,
		EnableProbe:     false,
		VerifyExecution: false,
	}
	e := NewEngine(cfg, zap.NewNop(), nil)
	e.SetPayloadPreset(payload.PayloadPreset(preset))
	return e
}

// The adaptive strategy must not lose findings: it changes dispatch order and
// in-flight accounting, not which candidates are selected or how they are scored.
//
// The assertion deliberately stops short of comparing the winning payload. The
// engine's group winner depends on completion order — the existing code notes that
// "随机marker/变异使主Payload可为同类不同变体" — so an exact-payload comparison
// would be flaky for reasons unrelated to scheduling. What must hold is that a
// positive fixture still yields a finding at all.
func TestAdaptiveStrategyStillFindsReflection(t *testing.T) {
	withAllowPrivate(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, q)
	}))
	defer server.Close()

	target := model.Target{URL: server.URL + "/?q=test"}
	for _, strategy := range []string{StrategyExhaustive, StrategyAdaptive} {
		e := newStrategyTestEngine("standard", strategy)
		res, err := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), target)
		if err != nil && res == nil {
			t.Fatalf("strategy %s: %v", strategy, err)
		}
		if res == nil {
			t.Fatalf("strategy %s returned no result", strategy)
		}
		if len(res.Findings) == 0 {
			t.Fatalf("strategy %s lost the reflection finding on a reflecting target", strategy)
		}
		for _, f := range res.Findings {
			if f.Parameter != "q" {
				t.Errorf("strategy %s attributed a finding to parameter %q", strategy, f.Parameter)
			}
			if f.Payload == "" {
				t.Errorf("strategy %s produced a finding without a payload", strategy)
			}
		}
	}
}

// A safe target must stay safe under both strategies: the bound must not turn a
// dropped candidate into a finding.
func TestAdaptiveStrategyKeepsSafeTargetClean(t *testing.T) {
	withAllowPrivate(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect nothing: the parameter is accepted but never echoed.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div>static</div></body></html>`)
	}))
	defer server.Close()

	e := newStrategyTestEngine("standard", StrategyAdaptive)
	res, _ := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/?q=test"})
	if res == nil {
		t.Fatal("no result")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("adaptive strategy reported findings on a non-reflecting target: %+v", res.Findings)
	}
}

// The per-path in-flight bound is the observable behaviour that separates
// adaptive from exhaustive: with a limit of 1, two requests for the same
// reflection path must never overlap.
func TestAdaptiveStrategySerializesPerPath(t *testing.T) {
	withAllowPrivate(t)
	var inFlight, peak int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&inFlight, 1)
		for {
			observed := atomic.LoadInt64(&peak)
			if current <= observed || atomic.CompareAndSwapInt64(&peak, observed, current) {
				break
			}
		}
		// Hold the request open long enough for an unbounded dispatcher to
		// overlap a second one.
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, q)
	}))
	defer server.Close()

	e := newStrategyTestEngine("full", StrategyAdaptive)
	e.config.Concurrency = 4
	res, _ := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/?q=test"})
	if res == nil {
		t.Fatal("no result")
	}
	if got := atomic.LoadInt64(&peak); got > 1 {
		t.Fatalf("adaptive strategy overlapped %d requests for the same path; the per-path bound is not in effect", got)
	}
}

// Explicit exhaustive must still allow overlap, so the
// comparison baseline the plan requires is genuinely unchanged.
func TestExhaustiveStrategyStillOverlaps(t *testing.T) {
	withAllowPrivate(t)
	var inFlight, peak int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&inFlight, 1)
		for {
			observed := atomic.LoadInt64(&peak)
			if current <= observed || atomic.CompareAndSwapInt64(&peak, observed, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, q)
	}))
	defer server.Close()

	e := newStrategyTestEngine("full", StrategyExhaustive)
	e.config.Concurrency = 4
	res, _ := e.Run(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL + "/?q=test"})
	if res == nil {
		t.Fatal("no result")
	}
	if got := atomic.LoadInt64(&peak); got < 2 {
		t.Fatalf("exhaustive strategy no longer overlaps requests (peak=%d); it is the unchanged baseline and must still pipeline", got)
	}
}

// Cancelling an adaptive scan must terminate promptly and report cancellation
// rather than hanging in the dispatcher. The dispatcher owns the task channel, so
// this exercises the shutdown path a mid-flight cancel takes.
func TestAdaptiveStrategyCancellationTerminates(t *testing.T) {
	withAllowPrivate(t)
	release := make(chan struct{})
	var started atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		// Block until the test releases, so cancellation happens while requests
		// are genuinely in flight.
		<-release
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, q)
	}))
	defer server.Close()
	defer close(release)

	e := newStrategyTestEngine("full", StrategyAdaptive)
	ctx, cancel := context.WithCancel(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}))
	done := make(chan struct{})
	var res *model.ScanResult
	var err error
	go func() {
		defer close(done)
		res, err = e.Run(ctx, model.Target{URL: server.URL + "/?q=test"})
	}()

	// Wait until the scan is genuinely under way, then cancel.
	deadline := time.After(10 * time.Second)
	for started.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("scan never issued a request")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("adaptive scan did not terminate after cancellation")
	}

	if res == nil {
		t.Fatal("cancelled scan returned no result; partial evidence must be preserved")
	}
	if res.Stats.Status != model.ScanCanceled {
		t.Fatalf("cancelled adaptive scan reported status %q, want %q", res.Stats.Status, model.ScanCanceled)
	}
	if err == nil {
		t.Fatal("cancelled scan returned no error")
	}
}

// Empty configuration uses adaptive; explicit exhaustive remains the baseline.
// Unknown library values retain the conservative fallback (CLI rejects them).
func TestStrategyResolutionDefaultsToAdaptive(t *testing.T) {
	cases := map[string]string{
		"":                   StrategyAdaptive,
		"exhaustive":         StrategyExhaustive,
		"adaptive":           StrategyAdaptive,
		"nonsense":           StrategyExhaustive,
		"ADAPTIVE":           StrategyExhaustive,
		"adaptive ":          StrategyExhaustive,
		"adaptive; rm -rf /": StrategyExhaustive,
	}
	for input, want := range cases {
		if got := (Config{Strategy: input}).strategyOrDefault(); got != want {
			t.Errorf("strategy %q resolved to %q, want %q", input, got, want)
		}
	}
}
