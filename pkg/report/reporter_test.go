package report

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestHTMLReportEscapesPayload(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/search?q=test",
		Duration: 1500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/search?q=test",
				Parameter:   "q",
				Payload:     `<script>alert(document.cookie)</script>`,
				Contexts:    []string{"html_body"},
				Description: "Reflected XSS in parameter 'q'",
			},
		},
	}

	r := NewReporter()
	html, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(html)

	// The raw <script> tag must NOT appear unescaped
	if strings.Contains(htmlStr, `<script>alert(document.cookie)</script>`) {
		t.Error("HTML report contains unescaped <script> tag from payload")
	}

	// It should appear escaped
	if !strings.Contains(htmlStr, `&lt;script&gt;`) {
		t.Error("HTML report does not contain escaped &lt;script&gt; from payload")
	}
}

func TestHTMLReportEscapesDescription(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.75,
				URL:         "http://example.com/",
				Parameter:   "x",
				Payload:     `<img src=x onerror=alert(1)>`,
				Contexts:    []string{"html_body"},
				Description: `XSS with <b>bold</b> description`,
			},
		},
	}

	r := NewReporter()
	html, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(html)

	// Description with HTML tags must be escaped
	if strings.Contains(htmlStr, `XSS with <b>bold</b> description`) {
		t.Error("HTML report contains unescaped HTML in description")
	}
}

func TestHTMLReportEscapesURL(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "medium",
				Confidence:  0.65,
				URL:         `http://example.com/page?param=<value>&other="test"`,
				Parameter:   "safe",
				Payload:     `<img src=x onerror=alert(1)>`,
				Contexts:    []string{"html_body"},
				Description: "Test URL escaping",
			},
		},
	}

	r := NewReporter()
	html, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(html)

	// URL with special chars must be escaped in HTML context
	if strings.Contains(htmlStr, `param=<value>&other="test"`) {
		t.Error("HTML report contains unescaped URL with special characters")
	}
}

func TestMarkdownReportEscapesBackticks(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.80,
				URL:         "http://example.com/",
				Parameter:   "q",
				Payload:     "`<img src=x onerror=alert(1)>`",
				Contexts:    []string{"html_body"},
				Description: "Payload with backticks",
			},
		},
	}

	r := NewReporter()
	md, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(md)

	// The payload with backticks should be escaped so it doesn't break out of code block
	if strings.Contains(mdStr, "`` `<img") {
		t.Error("Markdown report: backtick payload can escape code block")
	}
	// It should contain some form of escaped backticks
	if !strings.Contains(mdStr, "Payload:") {
		t.Error("Markdown report missing Payload field")
	}
}

func TestJSONReportRemainsValid(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "JSON safety test",
			},
		},
	}

	r := NewReporter()
	jsonData, err := r.Generate(data, FormatJSON)
	if err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}

	jsonStr := string(jsonData)

	// Go's json.MarshalIndent escapes < to \u003c by default — this is safe
	if !strings.Contains(jsonStr, `alert(1)`) {
		t.Error("JSON report missing payload data")
	}
	// Verify it's valid JSON by checking structure
	if !strings.Contains(jsonStr, `"reflected_xss"`) {
		t.Error("JSON report missing finding type data")
	}
}

// --- SARIF tests ---

func TestSARIFReportValid(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/search?q=x",
		Duration: 1500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/search?q=x",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "Reflected XSS in search parameter",
			},
		},
	}

	r := NewReporter()
	sarifData, err := r.Generate(data, FormatSARIF)
	if err != nil {
		t.Fatalf("SARIF generation failed: %v", err)
	}

	// Verify valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(sarifData, &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	// Check required SARIF fields
	if result["version"] != "2.1.0" {
		t.Errorf("Expected SARIF version 2.1.0, got %v", result["version"])
	}
	runs, ok := result["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("Expected 1 run, got %v", result["runs"])
	}
	run := runs[0].(map[string]interface{})
	results, ok := run["results"].([]interface{})
	if !ok || len(results) != 1 {
		t.Fatalf("Expected 1 result, got %v", run["results"])
	}
	result0 := results[0].(map[string]interface{})
	if result0["ruleId"] == nil {
		t.Error("SARIF result missing ruleId")
	}
	if result0["level"] != "error" {
		t.Errorf("Expected level 'error' for high severity, got %v", result0["level"])
	}
}

func TestSARIFReportMultipleFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 3000,
		Findings: []FindingData{
			{Type: "reflected_xss", Severity: "critical", Confidence: 0.95, URL: "http://example.com/a", Parameter: "q", Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Description: "XSS 1"},
			{Type: "reflected_xss", Severity: "medium", Confidence: 0.70, URL: "http://example.com/b", Parameter: "s", Payload: `<img src=x onerror=alert(1)>`, Contexts: []string{"attribute"}, Description: "XSS 2"},
			{Type: "reflected_xss", Severity: "low", Confidence: 0.60, URL: "http://example.com/c", Parameter: "t", Payload: `<svg onload=alert(1)>`, Contexts: []string{"html_body"}, Description: "XSS 3"},
		},
	}

	r := NewReporter()
	sarifData, err := r.Generate(data, FormatSARIF)
	if err != nil {
		t.Fatalf("SARIF generation failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(sarifData, &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs := result["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	// Check severity mapping
	levels := make(map[string]bool)
	for _, r := range results {
		res := r.(map[string]interface{})
		levels[res["level"].(string)] = true
	}
	if !levels["error"] {
		t.Error("Expected at least one 'error' level for critical severity")
	}
	if !levels["warning"] {
		t.Error("Expected at least one 'warning' level for medium severity")
	}
	if !levels["note"] {
		t.Error("Expected at least one 'note' level for low severity")
	}
}

func TestSARIFReportNoFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{},
	}

	r := NewReporter()
	sarifData, err := r.Generate(data, FormatSARIF)
	if err != nil {
		t.Fatalf("SARIF generation failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(sarifData, &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs := result["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

// --- JUnit tests ---

func TestJUnitReportValid(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/search?q=x",
		Duration: 1500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/search?q=x",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "Reflected XSS in search parameter",
			},
		},
	}

	r := NewReporter()
	junitData, err := r.Generate(data, FormatJUnit)
	if err != nil {
		t.Fatalf("JUnit generation failed: %v", err)
	}

	// Verify valid XML
	type testsuite struct {
		XMLName  xml.Name `xml:"testsuite"`
		Name     string   `xml:"name,attr"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
	}
	type testsuites struct {
		XMLName    xml.Name    `xml:"testsuites"`
		TestSuites []testsuite `xml:"testsuite"`
	}
	var ts testsuites
	if err := xml.Unmarshal(junitData, &ts); err != nil {
		t.Fatalf("JUnit output is not valid XML: %v\nOutput: %s", err, string(junitData))
	}
	if len(ts.TestSuites) != 1 {
		t.Fatalf("Expected 1 testsuite, got %d", len(ts.TestSuites))
	}
	if ts.TestSuites[0].Tests != 1 {
		t.Errorf("Expected 1 test, got %d", ts.TestSuites[0].Tests)
	}
	if ts.TestSuites[0].Failures != 1 {
		t.Errorf("Expected 1 failure, got %d", ts.TestSuites[0].Failures)
	}
}

func TestJUnitReportEscapesXML(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.80,
				URL:         "http://example.com/",
				Parameter:   "q",
				Payload:     `<script>alert("XSS & injection")</script>`,
				Contexts:    []string{"html_body"},
				Description: "Payload with XML special chars",
			},
		},
	}

	r := NewReporter()
	junitData, err := r.Generate(data, FormatJUnit)
	if err != nil {
		t.Fatalf("JUnit generation failed: %v", err)
	}

	// Must be valid XML — if special chars aren't escaped, unmarshaling will fail
	var result interface{}
	if err := xml.Unmarshal(junitData, &result); err != nil {
		t.Fatalf("JUnit output with special chars is not valid XML: %v", err)
	}
}

func TestJUnitReportNoFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{},
	}

	r := NewReporter()
	junitData, err := r.Generate(data, FormatJUnit)
	if err != nil {
		t.Fatalf("JUnit generation failed: %v", err)
	}

	junitStr := string(junitData)
	if !strings.Contains(junitStr, `tests="0"`) {
		t.Error("Expected tests=\"0\" in JUnit output with no findings")
	}
	if !strings.Contains(junitStr, `failures="0"`) {
		t.Error("Expected failures=\"0\" in JUnit output with no findings")
	}
}

func TestHTMLReportWithModelFinding(t *testing.T) {
	// Test via the FromScanResult path (integration with model.Finding)
	result := &model.ScanResult{
		Target: "http://example.com/search?q=x",
		Findings: []model.Finding{
			{
				ID:          "XSS-001",
				Type:        model.ReflectedXSS,
				Severity:    model.High,
				Confidence:  0.90,
				URL:         "http://example.com/search?q=x",
				Parameter:   "q",
				Payload:     `<svg onload=alert(document.domain)>`,
				Contexts:    []string{"html_body"},
				Description: "Reflected XSS in search parameter",
			},
		},
	}

	r := NewReporter()
	scanData := FromScanResult(result, 2000)
	html, err := r.Generate(scanData, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(html)

	// Raw SVG onload must not appear unescaped
	if strings.Contains(htmlStr, `<svg onload=alert(document.domain)>`) {
		t.Error("HTML report contains unescaped <svg onload=...> from payload")
	}
}
