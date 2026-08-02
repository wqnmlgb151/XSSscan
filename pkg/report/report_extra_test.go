package report

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

// ---------------------------------------------------------------------------
// Unit tests for internal helpers: buildPOCURL, buildCurlPOC, shellSingleQuote, buildCurlCommand
// ---------------------------------------------------------------------------

func TestBuildPOCURL(t *testing.T) {
	tests := []struct {
		name      string
		targetURL string
		param     string
		payload   string
		paramType model.ParamType
		want      string
	}{
		{
			name:      "query param injects payload",
			targetURL: "http://example.com/page?q=test",
			param:     "q",
			payload:   `<script>alert(1)</script>`,
			paramType: model.ParamQuery,
			want:      "http://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
		},
		{
			name:      "empty URL returns empty",
			targetURL: "",
			param:     "q",
			payload:   "x",
			paramType: model.ParamQuery,
			want:      "",
		},
		{
			name:      "empty param returns empty",
			targetURL: "http://example.com/",
			param:     "",
			payload:   "x",
			paramType: model.ParamQuery,
			want:      "",
		},
		{
			name:      "empty payload returns empty",
			targetURL: "http://example.com/",
			param:     "q",
			payload:   "",
			paramType: model.ParamQuery,
			want:      "",
		},
		{
			name:      "body param returns empty",
			targetURL: "http://example.com/",
			param:     "data",
			payload:   "x",
			paramType: model.ParamBody,
			want:      "",
		},
		{
			name:      "header param returns empty",
			targetURL: "http://example.com/",
			param:     "X-Custom",
			payload:   "x",
			paramType: model.ParamHeader,
			want:      "",
		},
		{
			name:      "cookie param returns empty",
			targetURL: "http://example.com/",
			param:     "session",
			payload:   "x",
			paramType: model.ParamCookie,
			want:      "",
		},
		{
			name:      "path param returns empty",
			targetURL: "http://example.com/",
			param:     "id",
			payload:   "x",
			paramType: model.ParamPath,
			want:      "",
		},
		{
			name:      "invalid URL returns empty",
			targetURL: "://invalid",
			param:     "q",
			payload:   "x",
			paramType: model.ParamQuery,
			want:      "",
		},
		{
			name:      "URL with existing query preserves other params",
			targetURL: "http://example.com/page?a=1&q=test&b=2",
			param:     "q",
			payload:   "POC",
			paramType: model.ParamQuery,
			want:      "http://example.com/page?a=1&b=2&q=POC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPOCURL(tt.targetURL, tt.param, tt.payload, tt.paramType)
			if got != tt.want {
				t.Errorf("buildPOCURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildCurlPOC(t *testing.T) {
	tests := []struct {
		name      string
		targetURL string
		param     string
		payload   string
		paramType model.ParamType
		want      string
	}{
		{
			name:      "query param builds curl command",
			targetURL: "http://example.com/page?q=test",
			param:     "q",
			payload:   `<script>alert(1)</script>`,
			paramType: model.ParamQuery,
			want:      "curl 'http://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'",
		},
		{
			name:      "empty URL returns empty",
			targetURL: "",
			param:     "q",
			payload:   "x",
			paramType: model.ParamQuery,
			want:      "",
		},
		{
			name:      "body param returns empty",
			targetURL: "http://example.com/",
			param:     "data",
			payload:   "x",
			paramType: model.ParamBody,
			want:      "",
		},
		{
			name:      "non-query param type returns empty",
			targetURL: "http://example.com/",
			param:     "q",
			payload:   "x",
			paramType: "",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCurlPOC(tt.targetURL, tt.param, tt.payload, tt.paramType)
			if got != tt.want {
				t.Errorf("buildCurlPOC() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShellSingleQuote(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no quotes", "hello world", "'hello world'"},
		{"single quote in middle", "it's", "'it'\\''s'"},
		{"multiple quotes", "a'b'c", "'a'\\''b'\\''c'"},
		{"leading quote", "'start", "''\\''start'"},
		{"trailing quote", "end'", "'end'\\'''"},
		{"only quotes", "'''", "''\\'''\\'''\\'''"},
		{"empty", "", "''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellSingleQuote(tt.in)
			if got != tt.want {
				t.Errorf("shellSingleQuote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildCurlCommand(t *testing.T) {
	tests := []struct {
		name    string
		rawReq  string
		scheme  string
		contain []string   // substrings that must appear in output
		absent  []string   // substrings that must NOT appear
		wantEmpty bool
	}{
		{
			name:      "empty raw request",
			rawReq:    "",
			scheme:    "http",
			wantEmpty: true,
		},
		{
			name:   "simple GET with Host header",
			rawReq: "GET /page?q=test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Go\r\n",
			scheme: "https",
			contain: []string{
				"curl -X GET",
				"https://example.com'/page?q=test'",
				"'User-Agent: Go'",
			},
		},
		{
			name:   "POST with body",
			rawReq: "POST /api/login HTTP/1.1\r\nHost: target.com\r\nContent-Length: 27\r\n\r\nusername=admin&password=x",
			scheme: "https",
			contain: []string{
				"curl -X POST",
				"https://target.com'/api/login'",
				"'username=admin&password=x'",
			},
			absent: []string{"Content-Length"},
		},
		{
			name:   "no Host header uses relative URL",
			rawReq: "GET /path HTTP/1.1\r\nUser-Agent: test\r\n",
			scheme: "http",
			contain: []string{"'/path'"},
		},
		{
			name:   "invalid request line returns empty",
			rawReq: "NOT_A_VALID_REQUEST_LINE",
			scheme: "http",
			// Fields splits into one token → len(parts) < 2 → empty
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCurlCommand(tt.rawReq, tt.scheme)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("expected empty, got %q", got)
				}
				return
			}
			for _, s := range tt.contain {
				if !strings.Contains(got, s) {
					t.Errorf("buildCurlCommand() missing %q\nGot: %s", s, got)
				}
			}
			for _, s := range tt.absent {
				if strings.Contains(got, s) {
					t.Errorf("buildCurlCommand() should not contain %q\nGot: %s", s, got)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HTML report: WAF section, CSP bypasses, execution badges, CurlPOC, empty
// ---------------------------------------------------------------------------

func TestHTMLReportWAFSection(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 1000,
		WAF: &model.WAFInfo{
			Name:     "Cloudflare",
			Bypassed: true,
		},
		Findings: []FindingData{},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(out)
	if !strings.Contains(htmlStr, "Cloudflare") {
		t.Error("HTML report missing WAF name")
	}
	if !strings.Contains(htmlStr, "Bypassed") {
		t.Error("HTML report missing bypassed status")
	}
}

func TestHTMLReportWAFNotBypassed(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 1000,
		WAF: &model.WAFInfo{
			Name:     "ModSecurity",
			Bypassed: false,
		},
		Findings: []FindingData{},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(out)
	if !strings.Contains(htmlStr, "ModSecurity") {
		t.Error("HTML report missing WAF name")
	}
	// Should NOT contain "Bypassed" when not bypassed
	if strings.Contains(htmlStr, "✅ Bypassed") {
		t.Error("HTML report should not show bypassed when WAF was not bypassed")
	}
}

func TestHTMLReportCSPBypassSection(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 1000,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/search?q=x",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "XSS with CSP bypass",
				CSPBypasses: []model.CSPBypass{
					{
						Type:        "jsonp",
						Description: "JSONP endpoint allows arbitrary callback",
						Exploit:     "callback=alert(1)//",
					},
					{
						Type:        "angular",
						Description: "AngularJS library on CDN",
						Exploit:     "{{constructor.constructor('alert(1)')()}}",
					},
				},
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(out)
	if !strings.Contains(htmlStr, "CSP Bypasses") {
		t.Error("HTML report missing CSP Bypasses section")
	}
	if !strings.Contains(htmlStr, "jsonp") {
		t.Error("HTML report missing jsonp CSP bypass type")
	}
	if !strings.Contains(htmlStr, "angular") {
		t.Error("HTML report missing angular CSP bypass type")
	}
}

func TestHTMLReportExecutionBadges(t *testing.T) {
	tests := []struct {
		name    string
		verified bool
		conf    float64
		want    string
	}{
		{
			name:     "verified badge",
			verified: true,
			conf:     0.95,
			want:     "Browser Verified",
		},
		{
			name:     "DOM mutation only badge",
			verified: false,
			conf:     0.50,
			want:     "DOM Mutation Only",
		},
		{
			name:     "structural only badge",
			verified: false,
			conf:     0.0,
			want:     "Structural Only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &ScanData{
				Target:   "http://example.com/",
				Duration: 500,
				Findings: []FindingData{
					{
						Type:                "reflected_xss",
						Severity:            "high",
						Confidence:          0.80,
						URL:                 "http://example.com/",
						Parameter:           "q",
						Payload:             `<img src=x onerror=alert(1)>`,
						Contexts:            []string{"html_body"},
						Description:         "Badge test",
						ExecutionVerified:   tt.verified,
						ExecutionConfidence: tt.conf,
					},
				},
			}

			r := NewReporter()
			out, err := r.Generate(data, FormatHTML)
			if err != nil {
				t.Fatalf("HTML generation failed: %v", err)
			}

			if !strings.Contains(string(out), tt.want) {
				t.Errorf("HTML report missing %q badge", tt.want)
			}
		})
	}
}

func TestHTMLReportCurlPOCSection(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/search?q=x",
				Scheme:      "https",
				Parameter:   "q",
				ParamType:   model.ParamQuery,
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "CurlPOC test",
				CurlPOC:     "curl 'https://example.com/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'",
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(out)
	if !strings.Contains(htmlStr, "Reproduce with curl") {
		t.Error("HTML report missing curl section")
	}
	if !strings.Contains(htmlStr, "Copy") {
		t.Error("HTML report missing copy button for curl POC")
	}
}

func TestHTMLReportRawRequestCurlFallback(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.80,
				URL:         "http://example.com/api",
				Scheme:      "https",
				Parameter:   "data",
				ParamType:   model.ParamBody,
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "Raw request curl fallback",
				RawRequest:  "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nx=<script>",
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(out)
	// Should contain curl command derived from raw request
	if !strings.Contains(htmlStr, "curl -X POST") {
		t.Error("HTML report missing curl command from raw request")
	}
	// Should contain "Copy for Burp" button
	if !strings.Contains(htmlStr, "Copy for Burp") {
		t.Error("HTML report missing 'Copy for Burp' button")
	}
}

func TestHTMLReportEmptyFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatHTML)
	if err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	htmlStr := string(out)
	if !strings.Contains(htmlStr, "No vulnerabilities found") {
		t.Error("HTML report missing 'No vulnerabilities found' message")
	}
}

// ---------------------------------------------------------------------------
// Markdown report: sections, WAF, CSP, empty, raw request/response, POC URL
// ---------------------------------------------------------------------------

func TestMarkdownReportContainsSections(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/search?q=test",
		Duration: 2000,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/search?q=test",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "Reflected XSS in search",
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(out)
	for _, section := range []string{"# XSS Scan Report", "## Findings", "Type:", "URL:", "Parameter:", "Payload:", "Confidence:", "Context:"} {
		if !strings.Contains(mdStr, section) {
			t.Errorf("Markdown report missing %q section/field", section)
		}
	}
}

func TestMarkdownReportWAFSection(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 1000,
		WAF: &model.WAFInfo{
			Name:     "AWS WAF",
			Bypassed: false,
		},
		Findings: []FindingData{},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(out)
	if !strings.Contains(mdStr, "## WAF Detection") {
		t.Error("Markdown report missing WAF Detection section")
	}
	if !strings.Contains(mdStr, "AWS WAF") {
		t.Error("Markdown report missing WAF name")
	}
	if !strings.Contains(mdStr, "Not bypassed") {
		t.Error("Markdown report missing 'Not bypassed' status")
	}
}

func TestMarkdownReportCSPBypasses(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 1000,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "CSP test",
				CSPBypasses: []model.CSPBypass{
					{
						Type:        "base-uri",
						Description: "Missing base-uri directive",
						Exploit:     "<base href=http://evil.com/>",
					},
				},
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(out)
	if !strings.Contains(mdStr, "CSP Bypasses") {
		t.Error("Markdown report missing CSP Bypasses field")
	}
	if !strings.Contains(mdStr, "base-uri") {
		t.Error("Markdown report missing CSP bypass type")
	}
}

func TestMarkdownReportEmptyFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(out)
	if !strings.Contains(mdStr, "No vulnerabilities found") {
		t.Error("Markdown report missing 'No vulnerabilities found' message")
	}
}

func TestMarkdownReportRawRequestResponse(t *testing.T) {
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
				Payload:     `<img src=x onerror=alert(1)>`,
				Contexts:    []string{"html_body"},
				Description: "Raw sections test",
				RawRequest:  "GET /?q=test HTTP/1.1\r\nHost: example.com",
				RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html",
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(out)
	if !strings.Contains(mdStr, "Raw Request") {
		t.Error("Markdown report missing Raw Request section")
	}
	if !strings.Contains(mdStr, "Raw Response") {
		t.Error("Markdown report missing Raw Response section")
	}
}

func TestMarkdownReportPOCURL(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{
			{
				Type:      "reflected_xss",
				Severity:  "high",
				Confidence: 0.80,
				URL:       "http://example.com/search?q=test",
				Parameter: "q",
				ParamType: model.ParamQuery,
				Payload:   `<script>alert(1)</script>`,
				Contexts:  []string{"html_body"},
				Description: "POC URL test",
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatMarkdown)
	if err != nil {
		t.Fatalf("Markdown generation failed: %v", err)
	}

	mdStr := string(out)
	if !strings.Contains(mdStr, "POC:") {
		t.Error("Markdown report missing POC link")
	}
}

// ---------------------------------------------------------------------------
// JSON report: empty findings, multiple findings
// ---------------------------------------------------------------------------

func TestJSONReportEmptyFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 500,
		Findings: []FindingData{},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatJSON)
	if err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}

	if result["Target"] != "http://example.com/" {
		t.Errorf("JSON report missing target, got %v", result["Target"])
	}
}

func TestJSONReportMultipleFindings(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 3000,
		Findings: []FindingData{
			{Type: "reflected_xss", Severity: "critical", Confidence: 0.95, URL: "http://example.com/a", Parameter: "q", Payload: `<script>alert(1)</script>`, Contexts: []string{"html_body"}, Description: "XSS 1"},
			{Type: "stored_xss", Severity: "high", Confidence: 0.85, URL: "http://example.com/b", Parameter: "name", Payload: `<img src=x onerror=alert(1)>`, Contexts: []string{"attribute"}, Description: "XSS 2"},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatJSON)
	if err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("JSON output is not valid: %v", err)
	}

	findings, ok := result["Findings"].([]interface{})
	if !ok {
		t.Fatal("JSON report missing findings array")
	}
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings in JSON, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// SARIF report: CSP bypasses in properties
// ---------------------------------------------------------------------------

func TestSARIFReportCSPBypassesInProperties(t *testing.T) {
	data := &ScanData{
		Target:   "http://example.com/",
		Duration: 1000,
		Findings: []FindingData{
			{
				Type:        "reflected_xss",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/",
				Parameter:   "q",
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "SARIF CSP test",
				CSPBypasses: []model.CSPBypass{
					{
						Type:        "jsonp",
						Description: "JSONP endpoint",
						Exploit:     "callback=alert(1)",
					},
				},
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, FormatSARIF)
	if err != nil {
		t.Fatalf("SARIF generation failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs := result["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	res0 := results[0].(map[string]interface{})

	props, ok := res0["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF result missing properties")
	}

	cspBypasses, ok := props["csp_bypasses"].(string)
	if !ok {
		t.Fatal("SARIF properties missing csp_bypasses field")
	}
	if !strings.Contains(cspBypasses, "jsonp") {
		t.Errorf("SARIF csp_bypasses missing bypass type, got %q", cspBypasses)
	}
	if !strings.Contains(cspBypasses, "JSONP endpoint") {
		t.Errorf("SARIF csp_bypasses missing description, got %q", cspBypasses)
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"unknown", "warning"}, // default
		{"", "warning"},        // default
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := sarifLevel(tt.severity)
			if got != tt.want {
				t.Errorf("sarifLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JUnit report: multiple findings
// ---------------------------------------------------------------------------

func TestJUnitReportMultipleFindings(t *testing.T) {
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
	out, err := r.Generate(data, FormatJUnit)
	if err != nil {
		t.Fatalf("JUnit generation failed: %v", err)
	}

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
	if err := xml.Unmarshal(out, &ts); err != nil {
		t.Fatalf("JUnit output is not valid XML: %v\nOutput: %s", err, string(out))
	}

	if len(ts.TestSuites) != 1 {
		t.Fatalf("Expected 1 testsuite, got %d", len(ts.TestSuites))
	}
	if ts.TestSuites[0].Tests != 3 {
		t.Errorf("Expected 3 tests, got %d", ts.TestSuites[0].Tests)
	}
	if ts.TestSuites[0].Failures != 3 {
		t.Errorf("Expected 3 failures, got %d", ts.TestSuites[0].Failures)
	}
}

// ---------------------------------------------------------------------------
// FromScanResult: WAF propagation, CurlPOC for query params
// ---------------------------------------------------------------------------

func TestFromScanResultWAFPropagation(t *testing.T) {
	result := &model.ScanResult{
		Target: "http://example.com/",
		Findings: []model.Finding{
			{
				Type:        model.ReflectedXSS,
				Severity:    model.High,
				Confidence:  0.85,
				URL:         "http://example.com/search?q=x",
				Parameter:   "q",
				ParamType:   model.ParamQuery,
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "WAF propagation test",
			},
		},
		Stats: model.ScanStats{
			WAF: &model.WAFInfo{
				Name:     "Cloudflare",
				Bypassed: true,
			},
		},
	}

	scanData := FromScanResult(result, 1500)
	if scanData.WAF == nil {
		t.Fatal("FromScanResult did not propagate WAF info")
	}
	if scanData.WAF.Name != "Cloudflare" {
		t.Errorf("WAF name = %q, want Cloudflare", scanData.WAF.Name)
	}
	if !scanData.WAF.Bypassed {
		t.Error("WAF bypassed flag not propagated")
	}
}

func TestFromScanResultCurlPOCForQueryParams(t *testing.T) {
	result := &model.ScanResult{
		Target: "http://example.com/",
		Findings: []model.Finding{
			{
				Type:        model.ReflectedXSS,
				Severity:    model.High,
				Confidence:  0.85,
				URL:         "http://example.com/search?q=test",
				Parameter:   "q",
				ParamType:   model.ParamQuery,
				Payload:     `<script>alert(1)</script>`,
				Contexts:    []string{"html_body"},
				Description: "Query param CurlPOC",
			},
			{
				Type:        model.ReflectedXSS,
				Severity:    model.Medium,
				Confidence:  0.70,
				URL:         "http://example.com/api",
				Parameter:   "data",
				ParamType:   model.ParamBody,
				Payload:     `<img src=x onerror=alert(1)>`,
				Contexts:    []string{"html_body"},
				Description: "Body param no CurlPOC",
			},
		},
	}

	scanData := FromScanResult(result, 1000)
	if len(scanData.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(scanData.Findings))
	}

	// Query param should have CurlPOC
	if scanData.Findings[0].CurlPOC == "" {
		t.Error("Query param finding should have CurlPOC set")
	}
	if !strings.Contains(scanData.Findings[0].CurlPOC, "curl") {
		t.Errorf("CurlPOC should contain 'curl', got %q", scanData.Findings[0].CurlPOC)
	}

	// Body param should NOT have CurlPOC
	if scanData.Findings[1].CurlPOC != "" {
		t.Errorf("Body param finding should not have CurlPOC, got %q", scanData.Findings[1].CurlPOC)
	}
}

func TestFromScanResultSchemeExtraction(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		scheme string
	}{
		{"https URL", "https://example.com/page?q=x", "https"},
		{"http URL", "http://example.com/page?q=x", "http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &model.ScanResult{
				Target: tt.url,
				Findings: []model.Finding{
					{
						Type:      model.ReflectedXSS,
						Severity:  model.High,
						Confidence: 0.80,
						URL:       tt.url,
						Parameter: "q",
						ParamType: model.ParamQuery,
						Payload:   `<img src=x onerror=alert(1)>`,
						Contexts:  []string{"html_body"},
					},
				},
			}

			scanData := FromScanResult(result, 500)
			if len(scanData.Findings) != 1 {
				t.Fatalf("Expected 1 finding, got %d", len(scanData.Findings))
			}
			if scanData.Findings[0].Scheme != tt.scheme {
				t.Errorf("Scheme = %q, want %q", scanData.Findings[0].Scheme, tt.scheme)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Default format fallback (unknown format → JSON)
// ---------------------------------------------------------------------------

func TestGenerateDefaultFormatFallback(t *testing.T) {
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
				Payload:     `<img src=x onerror=alert(1)>`,
				Contexts:    []string{"html_body"},
				Description: "Default format test",
			},
		},
	}

	r := NewReporter()
	out, err := r.Generate(data, OutputFormat("unknown-format"))
	if err != nil {
		t.Fatalf("Default format generation failed: %v", err)
	}

	// Should produce valid JSON (the default fallback)
	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("Default format output is not valid JSON: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Write helper
// ---------------------------------------------------------------------------

func TestWriteCreatesFile(t *testing.T) {
	// Use a temp file path
	path := t.TempDir() + "/test-report.json"
	data := []byte(`{"test": true}`)

	r := NewReporter()
	if err := r.Write(data, path); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify file was created and content is correct
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(content) != string(data) {
		t.Errorf("File content = %q, want %q", string(content), string(data))
	}
}

func TestWriteInvalidPath(t *testing.T) {
	r := NewReporter()
	// Empty path should fail
	err := r.Write([]byte("data"), "")
	if err == nil {
		t.Error("Expected error for empty path, got nil")
	}
}
