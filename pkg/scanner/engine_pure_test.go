package scanner

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/analyze"
	ctx "github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
)

// --- buildRawRequest ---

func TestBuildRawRequest_SimpleGET(t *testing.T) {
	target := model.Target{URL: "http://example.com/path?q=test", Method: "GET"}
	req := buildRawRequest(target)

	if !strings.Contains(req, "GET /path?q=test HTTP/1.1\r\n") {
		t.Errorf("Expected request line, got:\n%s", req)
	}
	if !strings.Contains(req, "Host: example.com\r\n") {
		t.Errorf("Expected Host header, got:\n%s", req)
	}
}

func TestBuildRawRequest_DefaultPath(t *testing.T) {
	target := model.Target{URL: "http://example.com", Method: "GET"}
	req := buildRawRequest(target)

	if !strings.Contains(req, "GET / HTTP/1.1\r\n") {
		t.Errorf("Expected default path '/', got:\n%s", req)
	}
}

func TestBuildRawRequest_POSTWithBody(t *testing.T) {
	target := model.Target{
		URL:    "http://example.com/api",
		Method: "POST",
		Body:   `{"key":"value"}`,
	}
	req := buildRawRequest(target)

	if !strings.Contains(req, "POST /api HTTP/1.1\r\n") {
		t.Errorf("Expected POST line, got:\n%s", req)
	}
	if !strings.Contains(req, "Content-Length: 15\r\n") {
		t.Errorf("Expected Content-Length, got:\n%s", req)
	}
	if !strings.Contains(req, `{"key":"value"}`) {
		t.Errorf("Expected body content, got:\n%s", req)
	}
}

func TestBuildRawRequest_CRLFStripping(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/test",
		Method:  "GET",
		Headers: map[string]string{"X-Injected": "value\r\nX-Evil: attack"},
	}
	req := buildRawRequest(target)

	if strings.Contains(req, "\r\nX-Evil") {
		t.Error("CRLF injection in header value was not stripped")
	}
}

func TestBuildRawRequest_Cookies(t *testing.T) {
	target := model.Target{
		URL:     "http://example.com/test",
		Method:  "GET",
		Cookies: []*http.Cookie{{Name: "session", Value: "abc123"}, {Name: "csrf", Value: "xyz"}},
	}
	req := buildRawRequest(target)

	if !strings.Contains(req, "Cookie: session=[REDACTED]; csrf=[REDACTED]\r\n") {
		t.Errorf("Expected Cookie header with redacted values, got:\n%s", req)
	}
}

func TestBuildRawRequest_InvalidURL(t *testing.T) {
	target := model.Target{URL: "http://[::1", Method: "GET"}
	req := buildRawRequest(target)

	// Should not panic; falls back to raw URL
	if !strings.Contains(req, "GET") {
		t.Errorf("Expected at least method, got:\n%s", req)
	}
}

// --- captureRawResponse ---

func TestCaptureRawResponse_SimpleResponse(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	body := []byte("<html>hello</html>")

	raw := captureRawResponse(resp, body)
	if !strings.HasPrefix(raw, "HTTP/1.1 200") {
		t.Errorf("Expected status line, got:\n%s", raw)
	}
	if !strings.Contains(raw, "Content-Type: text/html\r\n") {
		t.Errorf("Expected header, got:\n%s", raw)
	}
	if !strings.Contains(raw, "<html>hello</html>") {
		t.Errorf("Expected body, got:\n%s", raw)
	}
}

func TestCaptureRawResponse_BodyTruncation(t *testing.T) {
	resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}}
	largeBody := []byte(strings.Repeat("x", rawResponseCap+100))

	raw := captureRawResponse(resp, largeBody)
	if !strings.Contains(raw, "[truncated]") {
		t.Errorf("Expected truncation marker for large body, got:\n%s", raw)
	}
}

func TestCaptureRawResponse_UnderLimit(t *testing.T) {
	resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{}}
	body := []byte("short body")

	raw := captureRawResponse(resp, body)
	if strings.Contains(raw, "[truncated]") {
		t.Error("Body under limit should not be truncated")
	}
}

// --- stripCRLF ---

func TestStripCRLF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"clean", "clean"},
		{"has\rnewline", "hasnewline"},
		{"has\nnewline", "hasnewline"},
		{"has\r\nboth", "hasboth"},
		{"", ""},
	}
	for _, tt := range tests {
		got := stripCRLF(tt.input)
		if got != tt.expected {
			t.Errorf("stripCRLF(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- findingDescription ---

func TestFindingDescription_Query(t *testing.T) {
	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "q", Type: model.ParamQuery},
	}
	p := payload.Payload{Context: ctx.ContextHTMLBody}

	desc := findingDescription(inj, p)
	expected := "Reflected XSS in query parameter 'q' (html_body)"
	if desc != expected {
		t.Errorf("Expected %q, got %q", expected, desc)
	}
}

func TestFindingDescription_Cookie(t *testing.T) {
	inj := model.InjectionPoint{
		Parameter: model.Parameter{Name: "session", Type: model.ParamCookie},
	}
	p := payload.Payload{Context: ctx.ContextJSString}

	desc := findingDescription(inj, p)
	expected := "Reflected XSS in cookie parameter 'session' (js_string)"
	if desc != expected {
		t.Errorf("Expected %q, got %q", expected, desc)
	}
}

// --- contextsToStrings ---

func TestContextsToStrings(t *testing.T) {
	tests := []struct {
		name     string
		ctxs     []ctx.Context
		expected []string
	}{
		{"empty", nil, nil},
		{"single", []ctx.Context{{Type: ctx.ContextHTMLBody}}, []string{"html_body"}},
		{"multiple", []ctx.Context{
			{Type: ctx.ContextHTMLBody},
			{Type: ctx.ContextJSString},
		}, []string{"html_body", "js_string"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contextsToStrings(tt.ctxs)
			if len(got) != len(tt.expected) {
				t.Fatalf("Expected %d items, got %d", len(tt.expected), len(got))
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("Item %d: expected %q, got %q", i, tt.expected[i], v)
				}
			}
		})
	}
}

// --- convertCSPBypasses ---

func TestConvertCSPBypasses_Nil(t *testing.T) {
	result := convertCSPBypasses(nil)
	if result != nil {
		t.Errorf("Expected nil for nil input, got %v", result)
	}
}

func TestConvertCSPBypasses_Multiple(t *testing.T) {
	angularExploit := "{{constructor.constructor('alert()')()"
	csp := &analyze.CSPPolicy{
		Bypasses: []analyze.CSPBypass{
			{Type: "jsonp", Description: "JSONP endpoint", Exploit: "http://x.com/callback=alert"},
			{Type: "angular", Description: "Angular library", Exploit: angularExploit},
		},
	}
	result := convertCSPBypasses(csp)
	if len(result) != 2 {
		t.Fatalf("Expected 2 bypasses, got %d", len(result))
	}
	if result[0].Type != "jsonp" {
		t.Errorf("Expected type 'jsonp', got %q", result[0].Type)
	}
	if result[1].Exploit != angularExploit {
		t.Errorf("Expected angular exploit, got %q", result[1].Exploit)
	}
}
