package main

import (
	"encoding/json"
	"github.com/wqnmlgb151/XSSscan/test/testenv"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/report"
)

func TestDefaultModuleCoverageLocalChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("full default DOM source matrix needs local Chrome")
	}
	defer saveCfg()()

	server := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>safe</body></html>"))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "coverage.json")
	cfg = ScanConfig{URL: server.URL + "?q=x", AllowPrivate: true, Workers: 1, RateLimit: 100, Timeout: 15, MaxPayload: 1, ModuleTimeout: 300, RequestBudget: 1000, TriggerURLs: []string{server.URL + "/view"}, StoredMaxPolls: 1, StoredPollInterval: 1, Output: output, Format: "json", Silent: true}
	if err := runScan(nil, nil); err == nil {
		t.Fatal("missing callback must retain incomplete status")
	}
	bytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var data report.ScanData
	if err := json.Unmarshal(bytes, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Modules) != 4 {
		t.Fatalf("missing default modules: %+v", data.Modules)
	}
	for _, module := range data.Modules {
		if module.Type == "blind" {
			if module.Status != model.ScanSkipped || module.Reason == "" {
				t.Fatalf("missing callback reason: %+v", module)
			}
		} else if module.Status != model.ScanCompleted {
			t.Fatalf("default detector incomplete: %+v", module)
		}
	}
}
