package scanner

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/model"
)

type adaptiveTestVerifier struct {
	mu            sync.Mutex
	calls, closes int
	check         func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error)
}

func (v *adaptiveTestVerifier) VerifyFinding(ctx context.Context, f model.Finding, target model.Target) (*execverify.ExecutionResult, error) {
	v.mu.Lock()
	v.calls++
	v.mu.Unlock()
	return v.check(ctx, f, target)
}

func TestAdaptiveVerificationBoundedAndCancellationJoins(t *testing.T) {
	e := NewEngine(Config{}, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var active atomic.Int64
	v := &adaptiveTestVerifier{check: func(ctx context.Context, _ model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		<-release
		return nil, ctx.Err()
	}}
	s := newAdaptiveVerification(ctx, e, model.Target{})
	s.open = func() (candidateVerifier, error) { return v, nil }
	finished := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := adaptiveCandidate(fmt.Sprint(i), "alert(1)")
			s.check(ctx, &f)
			finished <- struct{}{}
		}()
	}
	// Always unblock workers on a failed assertion as well.
	defer func() { cancel(); unblock(); wg.Wait(); s.Close() }()
	for range 4 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("four checks did not start")
		}
	}
	cancel()
	for range 4 {
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Fatal("queued checks did not cancel")
		}
	}
	v.mu.Lock()
	calls := v.calls
	v.mu.Unlock()
	if calls != 4 || active.Load() != 4 {
		t.Fatalf("concurrency bound failed: calls=%d active=%d", calls, active.Load())
	}
	unblock()
	wg.Wait()
	s.Close()
	cov := e.runCoverage[0]
	if active.Load() != 0 || v.closes != 1 || cov.Planned != 8 || cov.Started != 4 || cov.Canceled != 4 || cov.NotStarted != 4 {
		t.Fatalf("workers not joined or coverage inconsistent: active=%d closes=%d coverage=%+v", active.Load(), v.closes, cov)
	}
}

func TestAdaptiveVerificationSetupPanicAndNilAreIncomplete(t *testing.T) {
	for _, panicSetup := range []bool{false, true} {
		t.Run(fmt.Sprint(panicSetup), func(t *testing.T) {
			e := NewEngine(Config{}, nil, nil)
			s := newAdaptiveVerification(context.Background(), e, model.Target{})
			s.open = func() (candidateVerifier, error) {
				if panicSetup {
					panic("setup failure")
				}
				return nil, nil
			}
			f := adaptiveCandidate("a", "alert(1)")
			s.check(context.Background(), &f)
			s.check(context.Background(), &f)
			s.Close()
			if f.ExecutionVerified || f.Evidence.VerificationError == "" || len(e.runIssues) != 1 || e.runCoverage[0].Started != 0 {
				t.Fatalf("setup failure hidden or retried: %+v %+v", f, e.runIssues)
			}
		})
	}
}

func (v *adaptiveTestVerifier) Close() error { v.closes++; return nil }

func adaptiveCandidate(path, value string) model.Finding {
	return model.Finding{ReflectionPath: path, Parameter: "q", ParamType: model.ParamQuery, Type: model.ReflectedXSS, Payload: value, Confidence: .8, RawRequest: "original-request"}
}

func TestAdaptiveVerificationReusesPositiveAndNegativeEvidence(t *testing.T) {
	e := NewEngine(Config{}, nil, nil)
	v := &adaptiveTestVerifier{check: func(_ context.Context, f model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		return &execverify.ExecutionResult{Executed: f.ReflectionPath == "positive", VerificationPayload: "exact-token"}, nil
	}}
	s := newAdaptiveVerification(context.Background(), e, model.Target{})
	s.open = func() (candidateVerifier, error) { return v, nil }
	positive := adaptiveCandidate("positive", "alert(1)")
	negative := adaptiveCandidate("negative", "confirm(1)")
	unsupported := adaptiveCandidate("positive", "custom()")
	s.check(context.Background(), &unsupported)
	s.check(context.Background(), &positive)
	s.check(context.Background(), &negative)
	got := s.finish([]model.Finding{positive, negative, unsupported})
	s.Close()
	s.Close()
	if v.calls != 2 || v.closes != 1 || len(got) != 2 {
		t.Fatalf("verification repeated or evidence lost: calls=%d closes=%d findings=%+v", v.calls, v.closes, got)
	}
	if len(e.runIssues) != 0 {
		t.Fatalf("unsupported alternative invalidated a proven group: %+v", e.runIssues)
	}
	for _, f := range got {
		if f.RawRequest != "original-request" || f.Evidence.VerificationPayload != "exact-token" {
			t.Fatalf("evidence changed: %+v", f)
		}
		if f.ReflectionPath == "positive" && (!f.ExecutionVerified || math.Abs(f.Confidence-.95) > 1e-9) {
			t.Fatalf("positive proof lost or boosted twice: %+v", f)
		}
		if f.ReflectionPath == "negative" && (f.ExecutionVerified || math.Abs(f.Confidence-.68) > 1e-9) {
			t.Fatalf("negative result lost or applied twice: %+v", f)
		}
	}
}

func TestAdaptiveVerificationFailureSurvivesLaterProofAndCancellation(t *testing.T) {
	e := NewEngine(Config{}, nil, nil)
	v := &adaptiveTestVerifier{check: func(_ context.Context, f model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		if f.Payload == "alert(1)" {
			return nil, errors.New("protocol failed")
		}
		return &execverify.ExecutionResult{Executed: true}, nil
	}}
	s := newAdaptiveVerification(context.Background(), e, model.Target{})
	s.open = func() (candidateVerifier, error) { return v, nil }
	defer s.Close()
	a, b := adaptiveCandidate("same", "alert(1)"), adaptiveCandidate("same", "confirm(1)")
	s.check(context.Background(), &a)
	s.check(context.Background(), &b)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	other := adaptiveCandidate("independent", "prompt(1)")
	s.check(canceled, &other)
	got := s.finish([]model.Finding{a, b, other})
	if v.calls != 2 || len(got) != 2 || !got[0].ExecutionVerified || got[1].ExecutionVerified || got[1].Evidence.VerificationError == "" {
		t.Fatalf("failure/cancellation lost or proof propagated: calls=%d findings=%+v", v.calls, got)
	}
	if len(e.runIssues) != 2 {
		t.Fatalf("diagnostics lost or duplicated: %+v", e.runIssues)
	}
}

func TestAdaptiveVerificationUnavailableAndUnsupportedRemainVisible(t *testing.T) {
	e := NewEngine(Config{}, nil, nil)
	s := newAdaptiveVerification(context.Background(), e, model.Target{})
	opens := 0
	s.open = func() (candidateVerifier, error) { opens++; return nil, errors.New("browser unavailable") }
	a, b := adaptiveCandidate("a", "alert(1)"), adaptiveCandidate("b", "confirm(1)")
	s.check(context.Background(), &a)
	s.check(context.Background(), &b)
	c := adaptiveCandidate("c", "custom()")
	s.check(context.Background(), &c)
	got := s.finish([]model.Finding{a, b, c})
	s.Close()
	if opens != 1 || len(got) != 3 || len(e.runIssues) != 2 {
		t.Fatalf("setup retried or errors hidden: opens=%d findings=%+v issues=%+v", opens, got, e.runIssues)
	}
	for _, f := range got {
		if f.ExecutionVerified || f.Evidence.VerificationError == "" {
			t.Fatalf("incomplete candidate lost: %+v", f)
		}
	}
	cov := e.runCoverage[0]
	if cov.Planned != 2 || cov.Started != 0 || cov.NotStarted != 2 {
		t.Fatalf("unavailable browser counted as execution: %+v", cov)
	}
}
