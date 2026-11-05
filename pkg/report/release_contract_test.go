package report

import (
	"encoding/json"
	"encoding/xml"
	"html"
	"strings"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestReleaseFormatsAgreeOnIncompleteStatusAndCoverage(t *testing.T) {
	data := &ScanData{Status: model.ScanCompleted, Duration: 1250, RequestsSent: 7, PayloadsSent: 3, Errors: 1,
		Modules:     []model.ModuleResult{{Type: "dom", Status: model.ScanPartial, Issues: []model.ScanIssue{{Stage: "browser", Message: "resource unavailable"}}}},
		Coverage:    []model.CheckCoverage{{Stage: "dom_source_checks", PlannedKnown: true, Planned: 10, Started: 3, Completed: 2, Failed: 1, NotStarted: 7}},
		CrossModule: []model.CrossModuleObservation{{Module: "dom", Kind: model.ObservationModuleIncomplete, Detail: "recorded module outcome"}}}
	for _, format := range []OutputFormat{FormatJSON, FormatMarkdown, FormatHTML, FormatSARIF, FormatJUnit} {
		t.Run(string(format), func(t *testing.T) {
			body, err := NewReporter().Generate(data, format)
			if err != nil {
				t.Fatal(err)
			}
			text := html.UnescapeString(string(body))
			if !strings.Contains(text, "partial") || !strings.Contains(text, "dom_source_checks") || !strings.Contains(text, "resource unavailable") || !strings.Contains(text, "recorded module outcome") || strings.Contains(text, "No vulnerabilities found") {
				t.Fatalf("inconsistent report: %s", text)
			}
			switch format {
			case FormatJSON:
				var got ScanData
				if err := json.Unmarshal(body, &got); err != nil || got.Status != model.ScanPartial || got.RequestsSent != 7 || got.Coverage[0].Started != 3 {
					t.Fatalf("bad JSON: %+v %v", got, err)
				}
			case FormatSARIF:
				var got sarifReport
				if err := json.Unmarshal(body, &got); err != nil || got.Runs[0].Invocations[0].ExecutionSuccessful || got.Runs[0].Invocations[0].Properties["requests_sent"] != float64(7) {
					t.Fatalf("bad SARIF: %+v %v", got, err)
				}
			case FormatJUnit:
				var got struct {
					Errors int    `xml:"errors,attr"`
					Time   string `xml:"time,attr"`
				}
				if err := xml.Unmarshal(body, &got); err != nil || got.Errors != 1 || got.Time != "1.250" {
					t.Fatalf("bad JUnit: %+v %v", got, err)
				}
			}
		})
	}
	if data.Status != model.ScanCompleted || len(data.Issues) != 0 {
		t.Fatal("report generation mutated its input")
	}
}

func TestReportPreservesBrowserWarningsAndExecutionEvidence(t *testing.T) {
	data := &ScanData{Findings: []FindingData{{ExecutionVerified: true, Evidence: model.Evidence{DialogMessage: "candidate-token", Diagnostics: []string{"save screenshot: unavailable"}}}}}
	for _, format := range []OutputFormat{FormatJSON, FormatMarkdown, FormatHTML, FormatSARIF, FormatJUnit} {
		body, err := NewReporter().Generate(data, format)
		if err != nil || !strings.Contains(string(body), "candidate-token") || !strings.Contains(string(body), "save screenshot: unavailable") {
			t.Fatalf("%s lost evidence: %s %v", format, body, err)
		}
	}
}

func TestReportDoesNotCountWrappedDiagnosticsAsNewFailures(t *testing.T) {
	data := &ScanData{Errors: 1, Issues: []model.ScanIssue{{Message: "failure"}, {Message: "scan incomplete: failure"}}}
	for _, format := range []OutputFormat{FormatJSON, FormatSARIF} {
		body, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		if format == FormatJSON {
			var got ScanData
			if err := json.Unmarshal(body, &got); err != nil || got.Errors != 1 {
				t.Fatalf("failure count changed: %s", body)
			}
		} else {
			var got sarifReport
			if err := json.Unmarshal(body, &got); err != nil || got.Runs[0].Invocations[0].Properties["errors"] != float64(1) {
				t.Fatalf("failure count changed: %s", body)
			}
		}
	}
}
