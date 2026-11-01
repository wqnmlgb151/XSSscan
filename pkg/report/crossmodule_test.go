package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

// The leads a module produced must reach the report, or nothing downstream can act on
// them. This checks the whole path — ScanResult to ScanData to serialized JSON — rather
// than the builder alone, because a summary that exists but is dropped during conversion
// provides no leads at all.
func TestCrossModuleSummaryReachesReport(t *testing.T) {
	result := &model.ScanResult{
		Target: "http://target/",
		Stats: model.ScanStats{
			Status: model.ScanPartial,
			WAF:    &model.WAFInfo{Name: "cloudflare", Bypassed: true},
			Modules: []model.ModuleResult{
				{Type: "reflected", Target: "http://target/", Status: model.ScanCompleted, Candidates: 20},
				{Type: "blind", Target: "http://target/", Status: model.ScanSkipped, Reason: "callback endpoint not configured"},
				{Type: "dom", Target: "http://target/", Status: model.ScanFailed, Reason: "chrome unavailable"},
			},
		},
	}
	result.Stats.CrossModule = model.BuildCrossModuleSummary(result.Stats.Modules, result.Stats.WAF, 1)

	data := FromScanResult(result, 100)
	if len(data.CrossModule) == 0 {
		t.Fatal("the summary was dropped during ScanResult conversion")
	}

	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	payload := string(encoded)
	for _, want := range []string{"cross_module", string(model.ObservationWAFAnswered), string(model.ObservationCallbackUnavailable)} {
		if !strings.Contains(payload, want) {
			t.Errorf("serialized report is missing %q", want)
		}
	}
	// The leads must not read as conclusions about the target anywhere in the output.
	for _, forbidden := range []string{"not vulnerable", "not exploitable", "target is safe"} {
		if strings.Contains(strings.ToLower(payload), forbidden) {
			t.Errorf("report states a conclusion the summary must not carry: %q", forbidden)
		}
	}
}

// An empty summary must not add noise to every report.
func TestEmptyCrossModuleSummaryIsOmitted(t *testing.T) {
	result := &model.ScanResult{Target: "http://target/", Stats: model.ScanStats{Status: model.ScanCompleted}}
	data := FromScanResult(result, 1)
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "cross_module") {
		t.Errorf("an empty summary was serialized: %s", encoded)
	}
}
