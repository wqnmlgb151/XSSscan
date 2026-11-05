package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestRunnerRejectsCompletedWithDiagnostics(t *testing.T) {
	for _, issues := range []bool{false, true} {
		r, _ := New(Plan{Types: []Type{Reflected}}, Module{Type: Reflected, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
			out := &model.ScanResult{Stats: model.ScanStats{Status: model.ScanCompleted, Errors: 1}}
			if issues {
				out.Stats.Issues = []model.ScanIssue{{Stage: "read", Message: "response interrupted"}}
			}
			return out, nil
		}})
		got, err := r.Run(context.Background(), model.Target{})
		if err == nil || got.Stats.Status != model.ScanPartial || len(got.Stats.Issues) == 0 {
			t.Fatalf("diagnostics falsely completed: %+v %v", got, err)
		}
	}
}

func TestRunnerTimeoutRetainsCompletedWorkWithoutFindings(t *testing.T) {
	r, _ := New(Plan{Types: []Type{Reflected}, ModuleTimeout: time.Millisecond}, Module{Type: Reflected, Run: func(ctx context.Context, _ model.Target) (*model.ScanResult, error) {
		<-ctx.Done()
		return &model.ScanResult{Stats: model.ScanStats{RequestsSent: 3}}, ctx.Err()
	}})
	got, err := r.Run(context.Background(), model.Target{})
	if !errors.Is(err, context.DeadlineExceeded) || got.Stats.Status != model.ScanPartial {
		t.Fatalf("completed work lost: %+v %v", got, err)
	}
}

func TestRunnerPreservesDistinctReturnedError(t *testing.T) {
	r, _ := New(Plan{Types: []Type{Reflected}}, Module{Type: Reflected, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
		return &model.ScanResult{Stats: model.ScanStats{Issues: []model.ScanIssue{{Stage: "read", Message: "first failure"}}}}, errors.New("second failure")
	}})
	got, _ := r.Run(context.Background(), model.Target{})
	var messages string
	for _, issue := range got.Stats.Issues {
		messages += issue.Message
	}
	if !strings.Contains(messages, "first failure") || !strings.Contains(messages, "second failure") {
		t.Fatalf("diagnostic erased: %+v", got.Stats.Issues)
	}
	if got.Stats.Errors != 2 {
		t.Fatalf("independent error not counted: %+v", got.Stats)
	}
}

func TestRunnerCountsNewDeadlineSeparatelyFromRecordedFailure(t *testing.T) {
	r, _ := New(Plan{Types: []Type{Reflected}, ModuleTimeout: time.Millisecond}, Module{Type: Reflected, Run: func(ctx context.Context, _ model.Target) (*model.ScanResult, error) {
		<-ctx.Done()
		return &model.ScanResult{Stats: model.ScanStats{Errors: 1, Issues: []model.ScanIssue{{Stage: "read", Message: "earlier failure"}}}}, nil
	}})
	got, err := r.Run(context.Background(), model.Target{})
	if !errors.Is(err, context.DeadlineExceeded) || got.Stats.Errors != 2 {
		t.Fatalf("deadline lost: %+v %v", got.Stats, err)
	}
}

func TestRunnerCountsUnknownJoinedErrorLeaves(t *testing.T) {
	r, _ := New(Plan{Types: []Type{Reflected}}, Module{Type: Reflected, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
		return &model.ScanResult{Stats: model.ScanStats{Errors: 1, Issues: []model.ScanIssue{{Stage: "read", Message: "old failure"}}}}, errors.Join(errors.New("old failure"), errors.New("new independent failure"))
	}})
	got, _ := r.Run(context.Background(), model.Target{})
	if got.Stats.Errors != 2 {
		t.Fatalf("joined failure not counted: %+v", got.Stats)
	}
}
