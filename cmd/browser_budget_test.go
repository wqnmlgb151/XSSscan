package main

import (
	"encoding/json"
	"errors"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/report"
	"github.com/wqnmlgb151/XSSscan/pkg/requestbudget"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserBudgetCLIIncompleteAndAccounting(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chrome")
	}
	defer saveCfg()()
	old := ssrfguard.AllowPrivate
	defer func() { ssrfguard.AllowPrivate = old }()
	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><link rel="icon" href="data:,"><script src="/script"></script><body>safe</body></html>`))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "budget.json")
	cfg = ScanConfig{URL: server.URL + "?q=x", Types: "dom", AllowPrivate: true, Workers: 1, RateLimit: 100, Timeout: 15, ModuleTimeout: 60, RequestBudget: 1000, BrowserRequestBudget: 1, Output: output, Format: "json", Silent: true}
	err := runScan(nil, nil)
	if !errors.Is(err, requestbudget.ErrBrowser) {
		t.Fatalf("missing budget cause: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var r report.ScanData
	if err = json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Status == model.ScanCompleted || len(r.Issues) == 0 || len(r.Modules) != 1 || r.Modules[0].Status == model.ScanCompleted {
		t.Fatalf("incomplete lost: %+v", r)
	}
	if !strings.Contains(string(data), "request_accounting") || !strings.Contains(string(data), "browser_http=1") {
		t.Fatal("missing counters")
	}
}
func TestBrowserBudgetYAMLAndValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "budget.yml")
	if err := os.WriteFile(p, []byte("browser-request-budget: 9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	var c ScanConfig
	f.ApplyTo(&c, nil)
	if c.BrowserRequestBudget != 9 {
		t.Fatal("YAML missing")
	}
	c.BrowserRequestBudget = 0
	f.ApplyTo(&c, map[string]bool{"browser-request-budget": true})
	if c.BrowserRequestBudget != 0 {
		t.Fatal("CLI zero override lost")
	}
	defer saveCfg()()
	cfg = ScanConfig{Types: "dom", BrowserRequestBudget: -1}
	if err = configureTypes(nil); err == nil {
		t.Fatal("negative budget allowed")
	}
}
