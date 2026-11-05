package main

import (
	"fmt"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fatih/color"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

func captureCLIStreams(t *testing.T, action func() error) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	stdout, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	oldOut, oldErr, oldColor := os.Stdout, os.Stderr, color.Output
	os.Stdout, os.Stderr, color.Output = stdout, stderr, stdout
	defer func() { os.Stdout, os.Stderr, color.Output = oldOut, oldErr, oldColor }()
	err = action()
	out, _ := os.ReadFile(stdout.Name())
	diagnostics, _ := os.ReadFile(stderr.Name())
	return string(out), string(diagnostics), err
}

func TestSilentConfigurationAndPipelineProduceNoStatus(t *testing.T) {
	defer saveCfg()()
	oldPrivate, oldNoColor := ssrfguard.AllowPrivate, color.NoColor
	defer func() { ssrfguard.AllowPrivate = oldPrivate; color.NoColor = oldNoColor }()
	var authenticated atomic.Int64
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			authenticated.Add(1)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<body>"+html.EscapeString(r.URL.Query().Get("q"))+"</body>")
	}))
	defer server.Close()
	for _, mode := range []string{"config", "targets file", "stdin"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			wordlist := filepath.Join(dir, "payloads.txt")
			if err := os.WriteFile(wordlist, []byte("<script>alert(1)</script>\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg = ScanConfig{URL: server.URL + "?q=test", Types: "reflected", AllowPrivate: true, Workers: 1, RateLimit: 10000, Timeout: 5, MaxPayload: 1, Silent: true, NoColor: true, JWT: "test-token", PayloadWordlist: wordlist, Output: filepath.Join(dir, "report.json"), Format: "json", Proxy: server.URL}
			if mode == "config" {
				cfg.Silent = false
				cfg.ConfigFile = filepath.Join(dir, "scan.yaml")
				if err := os.WriteFile(cfg.ConfigFile, []byte("silent: true\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				cfg.URL = ""
				input := filepath.Join(dir, "targets.txt")
				if err := os.WriteFile(input, []byte(server.URL+"?q=test\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if mode == "stdin" {
					file, err := os.Open(input)
					if err != nil {
						t.Fatal(err)
					}
					defer file.Close()
					oldInput := os.Stdin
					os.Stdin = file
					defer func() { os.Stdin = oldInput }()
					cfg.TargetsFile = "-"
				} else {
					cfg.TargetsFile = input
				}
			}
			out, diagnostics, err := captureCLIStreams(t, func() error { return runScan(nil, nil) })
			if err != nil || out != "" || diagnostics != "" {
				t.Fatalf("silent output leaked: stdout=%q stderr=%q err=%v", out, diagnostics, err)
			}
			if _, err := os.Stat(cfg.Output); err != nil {
				t.Fatalf("silent lost report: %v", err)
			}
		})
	}
	if authenticated.Load() == 0 {
		t.Fatal("silent configuration lost JWT")
	}
}

func TestStatusOutputStaysOnStderr(t *testing.T) {
	defer saveCfg()()
	cfg.Silent = false
	out, diagnostics, err := captureCLIStreams(t, func() error { statusCyan("ready %d", 2); statusYellow("warning"); statusGreen("done"); return nil })
	if err != nil || out != "" || !strings.Contains(diagnostics, "ready 2") || !strings.Contains(diagnostics, "warning") || !strings.Contains(diagnostics, "done") {
		t.Fatalf("status routing: %q %q %v", out, diagnostics, err)
	}
}
