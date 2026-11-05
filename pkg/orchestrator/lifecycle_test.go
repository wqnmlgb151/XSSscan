package orchestrator

import (
	"context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"testing"
	"time"
)

func TestPreflightDeadlinePanicAndMissingResult(t *testing.T) {
	for _, mode := range []string{"deadline", "panic", "nil"} {
		t.Run(mode, func(t *testing.T) {
			module := Module{Type: Reflected, Run: func(context.Context, model.Target) (*model.ScanResult, error) { return nil, nil }}
			if mode != "nil" {
				module.Check = func(ctx context.Context, _ model.Target) error {
					if mode == "panic" {
						panic("preflight")
					}
					<-ctx.Done()
					return ctx.Err()
				}
			}
			r, _ := New(Plan{Types: []Type{Reflected}, ModuleTimeout: time.Millisecond}, module)
			out, err := r.Run(context.Background(), model.Target{})
			if err == nil || out.Stats.Modules[0].Status == model.ScanCompleted || out.Stats.Modules[0].Reason == "" {
				t.Fatalf("lost failure: %+v %v", out, err)
			}
		})
	}
}

func TestModulesDoNotShareMutableTarget(t *testing.T) {
	r, _ := New(Plan{Types: []Type{Reflected, DOM}}, Module{Type: Reflected, Run: func(_ context.Context, target model.Target) (*model.ScanResult, error) {
		target.Headers["Authorization"] = "mutated"
		return &model.ScanResult{}, nil
	}}, Module{Type: DOM, Run: func(_ context.Context, target model.Target) (*model.ScanResult, error) {
		if target.Headers["Authorization"] != "original" {
			t.Fatal("module leaked target mutation")
		}
		return &model.ScanResult{}, nil
	}})
	_, err := r.Run(context.Background(), model.Target{Headers: map[string]string{"Authorization": "original"}})
	if err != nil {
		t.Fatal(err)
	}
}
