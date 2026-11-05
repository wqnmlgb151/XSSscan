package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestDefaultAllAndExplicitSelection(t *testing.T) {
	for _, selection := range []string{"", "all", "reflected,stored"} {
		kinds, err := Select(selection, "")
		if err != nil {
			t.Fatal(err)
		}
		var modules []Module
		called := make(map[Type]int)
		for _, kind := range types {
			kind := kind
			modules = append(modules, Module{Type: kind, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
				called[kind]++
				return &model.ScanResult{}, nil
			}})
		}
		runner, err := New(Plan{Types: kinds}, modules...)
		if err != nil {
			t.Fatal(err)
		}
		result, err := runner.Run(context.Background(), model.Target{URL: "http://example.test"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Stats.Modules) != len(kinds) || len(called) != len(kinds) {
			t.Fatalf("not all selected modules executed: %+v", result.Stats.Modules)
		}
	}
	if _, err := Select("all", "reflected,dom,stored,blind"); err == nil {
		t.Fatal("accepted empty selection")
	}
	if _, err := Select("other", ""); err == nil {
		t.Fatal("accepted unknown type")
	}
}

func TestUnavailableFailureAndCancellationCoverage(t *testing.T) {
	runner, _ := New(Plan{}, Module{Type: Reflected, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
		return &model.ScanResult{Findings: []model.Finding{{Payload: "proof"}}}, nil
	}}, Module{Type: DOM, Check: func(context.Context, model.Target) error { return fmt.Errorf("Chrome missing") }, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
		t.Fatal("unavailable module ran")
		return nil, nil
	}}, Module{Type: Stored, Run: func(context.Context, model.Target) (*model.ScanResult, error) { panic("detector failed") }})
	result, err := runner.Run(context.Background(), model.Target{})
	if err == nil || len(result.Stats.Modules) != 4 || len(result.Findings) != 1 || result.Stats.Status != model.ScanPartial {
		t.Fatalf("lost partial coverage: %+v %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = runner.Run(ctx, model.Target{})
	if !errors.Is(err, context.Canceled) || len(result.Stats.Modules) != 4 {
		t.Fatalf("lost canceled modules: %+v %v", result, err)
	}
}

func TestModuleDeadlinePreservesOtherModules(t *testing.T) {
	runner, _ := New(Plan{Types: []Type{Reflected, DOM}, ModuleTimeout: 10 * time.Millisecond}, Module{Type: Reflected, Run: func(ctx context.Context, _ model.Target) (*model.ScanResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}, Module{Type: DOM, Run: func(context.Context, model.Target) (*model.ScanResult, error) { return &model.ScanResult{}, nil }})
	result, err := runner.Run(context.Background(), model.Target{})
	if !errors.Is(err, context.DeadlineExceeded) || result.Stats.Modules[1].Status != model.ScanCompleted {
		t.Fatalf("deadline stopped independent module: %+v %v", result, err)
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestConcurrentRequestBudget(t *testing.T) {
	var sends atomic.Int64
	budget := &BudgetTransport{Max: 5, Base: transportFunc(func(*http.Request) (*http.Response, error) {
		sends.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://example.test", nil)
			resp, err := budget.RoundTrip(req)
			if err == nil {
				resp.Body.Close()
			} else if !errors.Is(err, ErrRequestBudget) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if sends.Load() != 5 || budget.Count() != 5 {
		t.Fatalf("budget overflow: %d %d", sends.Load(), budget.Count())
	}
}

func TestRunnerRetainsFailureCountAfterDiagnosticDedup(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		reported, issues, want int
	}{{"repeated failures", 8, 1, 8}, {"legacy detector without count", 0, 2, 2}, {"count without diagnostics", 3, 0, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			runner, _ := New(Plan{Types: []Type{Reflected, DOM}}, Module{Type: Reflected, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
				issues := make([]model.ScanIssue, tc.issues)
				for i := range issues {
					issues[i] = model.ScanIssue{Stage: "request", Message: fmt.Sprintf("failure %d", i)}
				}
				return &model.ScanResult{Stats: model.ScanStats{Errors: tc.reported, Issues: issues, Status: model.ScanPartial}}, fmt.Errorf("request failed")
			}}, Module{Type: DOM, Check: func(context.Context, model.Target) error { return fmt.Errorf("Chrome missing") }, Run: func(context.Context, model.Target) (*model.ScanResult, error) {
				t.Fatal("preflight failure ran module")
				return nil, nil
			}})
			got, err := runner.Run(context.Background(), model.Target{})
			want := tc.want + 1
			if tc.issues > 0 {
				want++
			} // The distinct returned error is retained too.
			if err == nil || got.Stats.Errors != want || len(got.Stats.Modules) != 2 {
				t.Fatalf("actual failures lost: %+v %v", got, err)
			}
			if len(got.Stats.Modules[0].Issues) != tc.issues+1 {
				t.Fatalf("diagnostics changed: %+v", got.Stats.Modules[0])
			}
		})
	}
}
