package main

import (
	"encoding/json"
	"github.com/xsscan/xsscan/pkg/report"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthenticationFailureStillWritesReproducibleReport(t *testing.T) {
	defer saveCfg()()
	old := ssrfguard.AllowPrivate
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form><input type="password"></form>`))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "failed.json")
	cfg = ScanConfig{Types: "reflected", URL: server.URL + "?q=x", AllowPrivate: true, Workers: 1, RateLimit: 100, Timeout: 2, MaxPayload: 1, LoginURL: server.URL + "/login", Username: "worker", Password: "original-secret", Output: output, Format: "json", Silent: true}
	if err := runScan(nil, nil); err == nil {
		t.Fatal("login form accepted as authenticated")
	}
	bytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var data report.ScanData
	if err := json.Unmarshal(bytes, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Issues) != 1 || data.Issues[0].HTTP == nil || !strings.Contains(data.Issues[0].HTTP.Request, "password=original-secret") || len(data.Modules) != 1 || data.Modules[0].Reason == "" {
		t.Fatalf("lost auth diagnostics: %+v", data)
	}
}
