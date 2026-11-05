package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"go.uber.org/zap"
)

func lifecycleCandidates(n int) []model.Finding {
	findings := make([]model.Finding, n)
	for i := range findings {
		findings[i] = model.Finding{ID: fmt.Sprint(i), Payload: "alert(1)", Confidence: .8, RawRequest: fmt.Sprintf("request-%d", i)}
	}
	return findings
}

func TestVerificationPanicRetainsPriorAndLaterResults(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	input := lifecycleCandidates(3)
	calls := 0
	got := e.verifyCandidateGroup(context.Background(), input, model.Target{}, func(_ context.Context, f model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		calls++
		if f.ID == "1" {
			panic("test verifier failure")
		}
		return &execverify.ExecutionResult{}, nil
	})
	if calls != 3 || len(got) != 3 || len(e.runIssues) == 0 {
		t.Fatalf("panic discarded results or diagnostics: calls=%d findings=%+v", calls, got)
	}
	for i, f := range got {
		if f.RawRequest != input[i].RawRequest || f.ExecutionVerified {
			t.Fatalf("evidence changed: %+v", f)
		}
		if i == 1 {
			if !strings.Contains(f.Evidence.VerificationError, "test verifier failure") || f.Confidence != input[i].Confidence {
				t.Fatalf("panic not recorded as incomplete: %+v", f)
			}
		} else if f.Evidence.VerificationError != "" || f.Confidence >= input[i].Confidence {
			t.Fatalf("completed negative check lost: %+v", f)
		}
	}
}

func TestVerificationPoolCancellationJoinsWorkersAndRetainsQueued(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input := lifecycleCandidates(40)
	groups := make([][]model.Finding, len(input))
	for i := range input {
		groups[i] = input[i : i+1]
	}
	started := make(chan struct{}, len(input))
	stopped := make(chan struct{}, len(input))
	release := make(chan struct{})
	defer close(release)
	var calls atomic.Int32
	done := make(chan []model.Finding, 1)
	go func() {
		done <- e.verifyGroups(ctx, groups, model.Target{}, func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error) {
			calls.Add(1)
			started <- struct{}{}
			<-ctx.Done()
			stopped <- struct{}{}
			<-release
			return nil, ctx.Err()
		})
	}()
	for range 4 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("workers failed to start")
		}
	}
	cancel()
	for range 4 {
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("workers did not receive cancellation")
		}
	}
	select {
	case <-done:
		t.Fatal("pool returned while verifiers still held browser resources")
	default:
	}
	for range 4 {
		release <- struct{}{}
	}
	var got []model.Finding
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pool did not finish after worker cleanup")
	}
	if len(got) != len(input) || calls.Load() != 4 {
		t.Fatalf("unexpected work after cancellation: findings=%d calls=%d", len(got), calls.Load())
	}
	coverage := e.runCoverage[0]
	if coverage.Planned != 40 || coverage.Started != 4 || coverage.Canceled != 4 || coverage.NotStarted != 36 {
		t.Fatalf("invalid cancellation coverage: %+v", coverage)
	}
	for i, f := range got {
		if f.ID != input[i].ID || f.RawRequest != input[i].RawRequest || f.Confidence != input[i].Confidence || f.ExecutionVerified || !strings.Contains(f.Evidence.VerificationError, "context canceled") {
			t.Fatalf("lost cancellation evidence: %+v", f)
		}
	}
}

func TestVerificationAlreadyCanceledNeedsNoBrowser(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := e.verifyGroupedFindings(ctx, lifecycleCandidates(2), nil, model.Target{})
	if len(got) != 2 {
		t.Fatalf("lost canceled findings: %+v", got)
	}
	for _, f := range got {
		if f.Evidence.VerificationError != context.Canceled.Error() {
			t.Fatalf("expected cancellation before browser setup: %+v", f)
		}
	}
}

func TestVerificationPanicRemainsDiagnosticAfterLaterProof(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	got := e.verifyCandidateGroup(context.Background(), lifecycleCandidates(2), model.Target{}, func(_ context.Context, f model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		if f.ID == "0" {
			panic("first candidate failed internally")
		}
		return &execverify.ExecutionResult{Executed: true, Confidence: .95}, nil
	})
	if len(got) != 1 || !got[0].ExecutionVerified || got[0].ID != "1" {
		t.Fatalf("later execution proof lost: %+v", got)
	}
	if len(e.runIssues) != 1 || !strings.Contains(e.runIssues[0].Message, "first candidate failed internally") || atomic.LoadInt64(&e.errors) != 1 {
		t.Fatalf("later proof erased panic diagnostic: %+v", e.runIssues)
	}
}

func TestVerificationCancellationRetainsEveryCandidate(t *testing.T) {
	for _, cancelBefore := range []bool{true, false} {
		t.Run(fmt.Sprint(cancelBefore), func(t *testing.T) {
			e := NewEngine(Config{}, zap.NewNop(), nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelBefore {
				cancel()
			}
			input := lifecycleCandidates(4)
			calls := 0
			got := e.verifyCandidateGroup(ctx, input, model.Target{}, func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error) {
				calls++
				cancel()
				return &execverify.ExecutionResult{}, nil
			})
			wantCalls := 1
			if cancelBefore {
				wantCalls = 0
			}
			if len(got) != len(input) || calls != wantCalls {
				t.Fatalf("lost candidates or continued verification: results=%d calls=%d", len(got), calls)
			}
			for i, f := range got {
				if f.ID != input[i].ID || f.RawRequest != input[i].RawRequest || f.ExecutionVerified {
					t.Fatalf("evidence changed: %+v", f)
				}
				if i >= wantCalls && (!strings.Contains(f.Evidence.VerificationError, "context canceled") || f.Confidence != input[i].Confidence) {
					t.Fatalf("unattempted candidate lost cancellation/structural confidence: %+v", f)
				}
				if input[i].Evidence.VerificationError != "" {
					t.Fatal("input mutated")
				}
			}
			if len(e.runIssues) == 0 {
				t.Fatal("cancellation absent from run diagnostics")
			}
		})
	}
}
