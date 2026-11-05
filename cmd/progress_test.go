package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"go.uber.org/zap"
)

func TestDefaultLoggerQuietAndVerboseOptIn(t *testing.T) {
	defer saveCfg()()
	for _, tc := range []struct{ verbose, silent, enabled bool }{{false, false, false}, {true, false, true}, {true, true, false}} {
		cfg.Verbose, cfg.Silent = tc.verbose, tc.silent
		logger := setupLogger()
		if logger.Core().Enabled(zap.InfoLevel) != tc.enabled {
			t.Fatal("unexpected logging policy")
		}
		_ = logger.Sync()
	}
}

func TestProgressStopsBeforeResultsAndDoesNotPolluteStdout(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprint(terminal), func(t *testing.T) {
			var out bytes.Buffer
			ctx, stop := startProgress(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), &out, terminal, time.Millisecond)
			model.ReportProgress(ctx, "DOM source checks", 3, 50)
			time.Sleep(15 * time.Millisecond)
			stop()
			stop()
			before := out.String()
			model.ReportProgress(ctx, "late event", 4, 50)
			time.Sleep(5 * time.Millisecond)
			if before != out.String() || !strings.Contains(before, "3/50") || strings.Contains(before, "\r") != terminal {
				t.Fatalf("bad progress lifecycle: %q", out.String())
			}
			if got := progressLine(model.Progress{Stage: "execution verification", Completed: 2, Total: 4}, 2*time.Second); !strings.Contains(got, "2/4") || !strings.Contains(got, "2s") {
				t.Fatal(got)
			}
		})
	}
}
