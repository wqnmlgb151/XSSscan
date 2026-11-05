package report

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestModuleCoverageWithoutFindings(t *testing.T) {
	data := FromScanResult(&model.ScanResult{Stats: model.ScanStats{Status: model.ScanPartial, Modules: []model.ModuleResult{{Type: "blind", Status: model.ScanSkipped, Reason: "callback missing <endpoint>"}}}}, 0)
	for _, format := range []OutputFormat{FormatJSON, FormatMarkdown, FormatHTML, FormatSARIF, FormatJUnit} {
		out, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "blind") || !strings.Contains(string(out), "skipped") || !strings.Contains(string(out), "callback missing") {
			t.Fatalf("%s lost coverage: %s", format, out)
		}
		if format == FormatJSON || format == FormatSARIF {
			var v any
			if err := json.Unmarshal(out, &v); err != nil {
				t.Fatal(err)
			}
		}
		if format == FormatJUnit {
			var v struct {
				Suite struct {
					Output string `xml:"system-out"`
				} `xml:"testsuite"`
			}
			if err := xml.Unmarshal(out, &v); err != nil || !strings.Contains(v.Suite.Output, "<endpoint>") {
				t.Fatalf("JUnit coverage: %s %v", out, err)
			}
		}
		if format == FormatHTML && strings.Contains(string(out), "<endpoint>") {
			t.Fatal("unescaped reason")
		}
	}
}
