package scanner

import (
	"context"
	"fmt"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
	"go.uber.org/zap"
)

// sentPayloads runs a scan against a recording fixture and returns the distinct
// request URIs the server actually received.
func sentPayloads(t *testing.T, strategy string) map[string]bool {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]bool{}
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.RawQuery] = true
		mu.Unlock()
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, q)
	}))
	defer server.Close()

	cfg := Config{
		Concurrency:    4,
		RateLimit:      1000,
		RateBurst:      2000,
		RequestTimeout: 5 * time.Second,
		MaxPayloads:    8,
		ConfidenceMin:  0.60,
		ConfidenceSet:  true,
		Strategy:       strategy,
		EnableProbe:    false,
	}
	e := NewEngine(cfg, zap.NewNop(), nil)
	if _, err := e.Run(context.Background(), model.Target{URL: server.URL + "/?q=test"}); err != nil {
		t.Logf("strategy %s returned error (may be expected): %v", strategy, err)
	}
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]bool, len(seen))
	for k := range seen {
		out[k] = true
	}
	return out
}

// Diagnostic: identify exactly which requests adaptive omits relative to
// exhaustive. This is a coverage investigation, not a pass/fail gate.
func TestWhichRequestsAdaptiveOmits(t *testing.T) {
	if testing.Short() {
		t.Skip("diagnostic")
	}
	ex := sentPayloads(t, StrategyExhaustive)
	ad := sentPayloads(t, StrategyAdaptive)

	t.Logf("exhaustive requests=%d adaptive requests=%d", len(ex), len(ad))
	for uri := range ex {
		if !ad[uri] {
			t.Logf("OMITTED BY ADAPTIVE: %s", uri)
		}
	}
	for uri := range ad {
		if !ex[uri] {
			t.Logf("ONLY IN ADAPTIVE: %s", uri)
		}
	}
}

// Deterministic coverage gate: the same injection point must yield the same
// candidate count under both strategies. Marker randomness affects the URI text
// but not how many candidates exist, so a count difference here is a real
// coverage change rather than noise.
func TestAdaptiveDispatchesEveryGeneratedCandidate(t *testing.T) {
	var mu sync.Mutex
	var perRequest []string
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		mu.Lock()
		perRequest = append(perRequest, q)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, q)
	}))
	defer server.Close()

	// Count candidates the generator would produce for this fixture, using the
	// same engine configuration the scan will use (no probe, no WAF bypass, so
	// the candidate set depends only on the detected contexts).
	countCandidates := func() int {
		cfg := Config{
			Strategy:    StrategyExhaustive,
			Concurrency: 4, RateLimit: 1000, RateBurst: 2000,
			RequestTimeout: 5 * time.Second, MaxPayloads: 8,
			ConfidenceMin: 0.60, ConfidenceSet: true, EnableProbe: false,
		}
		e := NewEngine(cfg, zap.NewNop(), nil)
		res, err := e.Run(context.Background(), model.Target{URL: server.URL + "/?q=test"})
		if err != nil || res == nil {
			t.Fatalf("candidate count run failed: %v", err)
		}
		return res.Stats.PayloadsSent
	}

	baseline := countCandidates()
	if baseline == 0 {
		t.Fatal("fixture generated no candidates")
	}
	for i := 0; i < 3; i++ {
		again := countCandidates()
		if again != baseline {
			t.Fatalf("candidate count is not deterministic for the baseline: %d then %d", baseline, again)
		}
	}

	cfg := Config{
		Concurrency: 4, RateLimit: 1000, RateBurst: 2000,
		RequestTimeout: 5 * time.Second, MaxPayloads: 8,
		ConfidenceMin: 0.60, ConfidenceSet: true, EnableProbe: false,
		Strategy: StrategyAdaptive,
	}
	e := NewEngine(cfg, zap.NewNop(), nil)
	res, err := e.Run(context.Background(), model.Target{URL: server.URL + "/?q=test"})
	if err != nil || res == nil {
		t.Fatalf("adaptive run failed: %v", err)
	}
	if got := res.Stats.PayloadsSent; got != baseline {
		t.Fatalf("adaptive dispatched %d payloads but the exhaustive baseline dispatches %d", got, baseline)
	}
}
