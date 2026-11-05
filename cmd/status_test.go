package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/report"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func TestPrivateBlockNeverPrintsCleanResult(t *testing.T) {
	defer saveCfg()()
	old := ssrfguard.AllowPrivate
	defer func() { ssrfguard.AllowPrivate = old }()
	var hits atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "blocked.json")
	cfg = ScanConfig{Types: "reflected", URL: server.URL + "?q=x", Output: output, Format: "json", Workers: 1, RateLimit: 100, Timeout: 2, MaxPayload: 1, AllowPrivate: false}
	var terminal bytes.Buffer
	oldOutput := color.Output
	color.Output = &terminal
	defer func() { color.Output = oldOutput }()
	if err := runScan(nil, nil); err == nil {
		t.Fatal("blocked scan returned success")
	}
	if hits.Load() != 0 {
		t.Fatal("blocked target received requests")
	}
	if strings.Contains(terminal.String(), "No XSS vulnerabilities found") {
		t.Fatal("blocked scan printed clean result")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var parsed report.ScanData
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Status != model.ScanFailed || len(parsed.Issues) == 0 {
		t.Fatalf("block not reported: %+v", parsed)
	}
	terminal.Reset()
	printResults(&model.ScanResult{Stats: model.ScanStats{Status: model.ScanCanceled}}, time.Second)
	if strings.Contains(terminal.String(), "No XSS vulnerabilities found") {
		t.Fatal("cancellation printed clean result")
	}
}

func TestRunScanPartialFailureWritesFindingsAndStatus(t *testing.T) {
	defer saveCfg()()
	old := ssrfguard.AllowPrivate
	defer func() { ssrfguard.AllowPrivate = old }()
	var hits atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/broken" {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<body>%s</body>", r.URL.Query().Get("q"))
	}))
	defer server.Close()
	list := filepath.Join(t.TempDir(), "targets.txt")
	output := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(list, []byte(server.URL+"/broken?q=x\n"+server.URL+"/ok?q=x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg = ScanConfig{Types: "reflected", URL: server.URL, TargetsFile: list, Output: output, Format: "json", Workers: 1, RateLimit: 10000, Timeout: 5, MaxPayload: 1, Silent: true, AllowPrivate: true}
	if err := runScan(nil, nil); err == nil {
		t.Fatal("partial batch reported success")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var parsed report.ScanData
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Status != model.ScanPartial || len(parsed.Findings) == 0 || len(parsed.Issues) == 0 {
		t.Fatalf("partial evidence lost: %+v", parsed)
	}
	if parsed.RequestsSent != int(hits.Load()) {
		t.Fatalf("requests %d != %d", parsed.RequestsSent, hits.Load())
	}
}

func TestScanAllTargetsCanceledReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var findings []model.Finding
	var stats model.ScanStats
	err := scanAllTargets(ctx, nil, nil, []string{"http://127.0.0.1"}, model.Target{}, &findings, &stats)
	if !errors.Is(err, context.Canceled) || stats.Status != model.ScanCanceled {
		t.Fatalf("cancellation lost: %+v %v", stats, err)
	}
}

func TestValidateConfigRejectsInvalidModes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		alter func(*ScanConfig)
	}{
		{"format", func(c *ScanConfig) { c.Format = "typo" }},
		{"workers", func(c *ScanConfig) { c.Workers = -1 }},
		{"confidence", func(c *ScanConfig) { c.ConfidenceMin = 1.1 }},
		{"nan", func(c *ScanConfig) { c.ConfidenceMin = math.NaN() }},
		{"preset", func(c *ScanConfig) { c.PayloadPreset = "typo" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := ScanConfig{URL: "http://127.0.0.1", Workers: 1}
			tt.alter(&c)
			if validateConfig(&c) == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
