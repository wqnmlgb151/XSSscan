package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
)

func TestCandidateEvidenceSurvivesAllFormats(t *testing.T) {
	evidence := model.Evidence{TriggerURL: "https://example.com/view", DetectionMethod: "stored_execution", VerificationPayload: `<img onerror=alert(1)>`, DialogMessage: "xsscanProof", Interaction: "synthetic mouseover"}
	data := FromScanResult(&model.ScanResult{Findings: []model.Finding{{URL: "https://example.com/save", Type: model.StoredXSS, Severity: model.High, Payload: "original", Evidence: evidence, ExecutionVerified: true}}}, 0)
	for _, format := range []OutputFormat{FormatJSON, FormatMarkdown, FormatHTML, FormatSARIF, FormatJUnit} {
		output, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{evidence.TriggerURL, evidence.DetectionMethod, evidence.DialogMessage, evidence.Interaction} {
			if format == FormatMarkdown {
				value = text.EscapeMarkdown(value)
			}
			if !strings.Contains(string(output), value) {
				t.Fatalf("%s lost %q", format, value)
			}
		}
		if (format == FormatHTML || format == FormatJUnit) && strings.Contains(string(output), evidence.VerificationPayload) {
			t.Fatalf("%s emitted unescaped probe", format)
		}
		switch format {
		case FormatJSON, FormatSARIF:
			var parsed interface{}
			if err := json.Unmarshal(output, &parsed); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(fmt.Sprint(parsed), evidence.VerificationPayload) {
				t.Fatalf("%s lost actual verification probe", format)
			}
		case FormatHTML, FormatJUnit:
			if !strings.Contains(string(output), html.EscapeString(evidence.VerificationPayload)) {
				t.Fatalf("%s lost escaped verification probe", format)
			}
		case FormatMarkdown:
			if !strings.Contains(string(output), text.EscapeMarkdown(evidence.VerificationPayload)) {
				t.Fatal("markdown lost verification probe")
			}
		}
	}
}

func TestVerificationFailureSurvivesAllReportFormats(t *testing.T) {
	evidence := model.Evidence{VerificationError: "browser navigation blocked <destination>", VerificationPayload: "candidate-probe"}
	data := FromScanResult(&model.ScanResult{Stats: model.ScanStats{Status: model.ScanPartial}, Findings: []model.Finding{{Type: model.ReflectedXSS, Severity: model.High, Payload: "original", Confidence: .9, Evidence: evidence}}}, 1)
	for _, format := range []OutputFormat{FormatJSON, FormatMarkdown, FormatHTML, FormatSARIF, FormatJUnit} {
		output, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		switch format {
		case FormatJSON, FormatSARIF:
			var parsed any
			if err := json.Unmarshal(output, &parsed); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(fmt.Sprint(parsed), evidence.VerificationError) {
				t.Fatalf("%s lost failure evidence", format)
			}
		case FormatMarkdown:
			if !strings.Contains(string(output), text.EscapeMarkdown(evidence.VerificationError)) {
				t.Fatal("markdown lost failure evidence")
			}
		default:
			if !strings.Contains(string(output), html.EscapeString(evidence.VerificationError)) {
				t.Fatalf("%s lost failure evidence", format)
			}
		}
		if format == FormatHTML && !strings.Contains(string(output), "Execution Verification Incomplete") {
			t.Fatal("HTML failed to distinguish incomplete verification")
		}
	}
}

func TestDataFlowHypothesisIsVisibleAndEscaped(t *testing.T) {
	flow := model.JSDataFlow{Source: "query", Key: "<img onerror=alert(1)>`|", Sink: "innerHTML", ScriptIndex: 2, SourceStart: 10, SourceEnd: 20, SinkStart: 30, SinkEnd: 40}
	evidence := model.Evidence{DataFlow: []model.JSDataFlow{flow}}
	fields := evidenceFields(evidence)
	if len(fields) != 1 || fields[0][0] != "Data Flow (static hypothesis)" || !strings.Contains(fields[0][1], "script #2; source bytes [10,20); sink bytes [30,40)") {
		t.Fatal(fields)
	}
	data := FromScanResult(&model.ScanResult{Findings: []model.Finding{{Type: model.DOMXSS, Evidence: evidence, Confidence: .65}}}, 0)
	for _, format := range []OutputFormat{FormatHTML, FormatMarkdown} {
		output, err := NewReporter().Generate(data, format)
		if err != nil {
			t.Fatal(err)
		}
		value := fields[0][1]
		if format == FormatHTML {
			value = html.EscapeString(value)
		} else {
			value = text.EscapeMarkdown(value)
		}
		if !strings.Contains(string(output), value) || !strings.Contains(string(output), fields[0][0]) || strings.Contains(string(output), flow.Key) {
			t.Fatalf("%s lost or failed to escape the static hypothesis", format)
		}
	}
}
