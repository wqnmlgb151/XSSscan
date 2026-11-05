package report

import (
	"encoding/json"
	"encoding/xml"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"strings"
	"testing"
)

func TestIncompleteStatusAcrossFormats(t *testing.T) {
	data := FromScanResult(&model.ScanResult{Stats: model.ScanStats{Status: model.ScanPartial, Issues: []model.ScanIssue{{Target: "http://local", Stage: "analysis", Message: "failed <request>"}}}}, 10)
	for _, format := range []OutputFormat{FormatJSON, FormatHTML, FormatMarkdown, FormatSARIF, FormatJUnit} {
		out, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "partial") || strings.Contains(string(out), "No vulnerabilities found") {
			t.Fatalf("misleading %s: %s", format, out)
		}
		if format == FormatJSON || format == FormatSARIF {
			var decoded any
			if err := json.Unmarshal(out, &decoded); err != nil {
				t.Fatal(err)
			}
		}
		if format == FormatJUnit {
			var doc struct {
				Errors int `xml:"errors,attr"`
			}
			if err := xml.Unmarshal(out, &doc); err != nil || doc.Errors != 1 {
				t.Fatalf("junit error not represented: %v", err)
			}
		}
	}
}
