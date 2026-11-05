package scanner

import (
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
)

func TestDefaultAdaptiveWaitsForProofAndPreservesIndependentParameters(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	withAllowPrivate(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><div>%s</div><div>%s</div></body></html>", r.URL.Query().Get("a"), r.URL.Query().Get("b"))
	}))
	defer server.Close()
	for _, strategy := range []string{"", StrategyExhaustive} {
		t.Run("strategy="+strategy, func(t *testing.T) {
			e := NewEngine(Config{Concurrency: 10, RateLimit: 1000, RateBurst: 100,
				RequestTimeout: 5 * time.Second, MaxPayloads: 20,
				VerifyExecution: true, VerifyTimeout: 5 * time.Second, Strategy: strategy}, nil, nil)
			ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 40*time.Second)
			defer cancel()
			result, err := e.Run(ctx, model.Target{URL: server.URL + "/?a=test&b=test"})
			if err != nil {
				t.Fatalf("scan failed: %v; %+v", err, result.Stats)
			}
			proven := make(map[string]bool)
			for _, f := range result.Findings {
				if f.ExecutionVerified {
					proven[f.Parameter] = true
				}
			}
			if !proven["a"] || !proven["b"] {
				t.Fatalf("proof suppressed an independent input: %+v", result.Findings)
			}
			sawCandidates, sawAdaptive := false, false
			for _, c := range result.Stats.Coverage {
				if c.Stage == "reflected_candidates" {
					sawCandidates = true
					if c.Planned != 40 {
						t.Fatalf("candidate range changed: %+v", c)
					}
					if strategy == "" && (c.Started >= c.Planned || c.NotStarted == 0) {
						t.Fatalf("default adaptive still dispatched the whole range: %+v", c)
					}
					if strategy == StrategyExhaustive && c.Started != c.Planned {
						t.Fatalf("exhaustive baseline changed: %+v", c)
					}
				}
				if c.Stage == "adaptive_verification_attempts" {
					sawAdaptive = true
					if c.Started != 2 || c.Completed != 2 || c.Failed != 0 {
						t.Fatalf("simple proofs repeated or failed: %+v", c)
					}
				}
			}
			if !sawCandidates || sawAdaptive != (strategy == "") {
				t.Fatalf("coverage stages missing or misattributed: %+v", result.Stats.Coverage)
			}
		})
	}
}

func TestDefaultAdaptiveKeepsAmbiguousReflectionCandidates(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	withAllowPrivate(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body><div>%s</div><p>%s</p></body></html>", q, q)
	}))
	defer server.Close()
	e := NewEngine(Config{Concurrency: 4, RateLimit: 1000, RateBurst: 100,
		RequestTimeout: 5 * time.Second, MaxPayloads: 4,
		VerifyExecution: true, VerifyTimeout: 5 * time.Second}, nil, nil)
	ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 40*time.Second)
	defer cancel()
	result, err := e.Run(ctx, model.Target{URL: server.URL + "/?q=test"})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	seen := false
	for _, c := range result.Stats.Coverage {
		if c.Stage == "reflected_candidates" {
			seen = true
			if c.Planned != 4 || c.Started != 4 || c.NotStarted != 0 {
				t.Fatalf("unattributed execution suppressed ambiguous positions' candidates: %+v", c)
			}
		}
	}
	if !seen || len(result.Findings) == 0 || !result.Findings[0].ExecutionVerified {
		t.Fatalf("evidence or coverage missing: %+v", result)
	}
}

func TestDefaultAdaptiveMixedFallbackDoesNotInheritProof(t *testing.T) {
	if testing.Short() {
		t.Skip("browser integration")
	}
	withAllowPrivate(t)
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><script>%s</script></body></html>", r.URL.Query().Get("q"))
	}))
	defer server.Close()
	e := NewEngine(Config{Concurrency: 4, RateLimit: 1000, RateBurst: 100,
		RequestTimeout: 5 * time.Second, VerifyExecution: true, VerifyTimeout: 5 * time.Second}, nil, nil)
	// Existing callback templates have HTMLBody metadata. They must remain
	// dispatchable as fallbacks alongside this unique JSBlock's direct candidates.
	// All endpoints are this local fixture; there is no external callback service.
	e.SetCallbackURL(server.URL + "/callback")
	e.SetPayloadPreset(payload.PresetMinimal)
	ctx, cancel := context.WithTimeout(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 40*time.Second)
	defer cancel()
	target := model.Target{URL: server.URL + "/?q=test"}
	analysis, err := e.analyzer.Analyze(ctx, target)
	if err != nil || len(analysis.InjectionPoints) != 1 {
		t.Fatalf("fixture analysis changed: %+v %v", analysis, err)
	}
	injection := analysis.InjectionPoints[0]
	tasks, err := buildScheduledTasks(target, injection, e.generatePayloads(injection, nil))
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[pathID]bool)
	allowed, fallback := false, false
	for _, task := range tasks {
		paths[task.path] = true
		allowed = allowed || task.canConverge
		fallback = fallback || !task.canConverge
	}
	if len(paths) != 1 || !allowed || !fallback {
		t.Fatalf("fixture must mix trusted and fallback candidates in one bucket: %+v", tasks)
	}
	result, err := e.Run(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v; %+v", err, result.Stats)
	}
	proven, sawCoverage := false, false
	for _, f := range result.Findings {
		proven = proven || f.ExecutionVerified
	}
	for _, c := range result.Stats.Coverage {
		if c.Stage == "reflected_candidates" {
			sawCoverage = true
			if c.Planned <= 1 || c.Started != c.Planned || c.NotStarted != 0 {
				t.Fatalf("fallback inherited another candidate's permission: %+v", c)
			}
		}
	}
	if !proven || !sawCoverage {
		t.Fatalf("test did not observe execution and coverage: %+v", result)
	}
}
