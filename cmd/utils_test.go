package main

import (
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
)

// --- Tests for cloneHeaders ---

func TestCloneHeaders_Nil(t *testing.T) {
	result := cloneHeaders(nil)
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}
}

func TestCloneHeaders_DeepCopy(t *testing.T) {
	src := map[string]string{"Authorization": "Bearer token", "X-Custom": "value"}
	dst := cloneHeaders(src)

	if len(dst) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(dst))
	}
	// Modify dst — src must be unaffected
	dst["Authorization"] = "modified"
	if src["Authorization"] != "Bearer token" {
		t.Error("cloneHeaders did not deep-copy: modifying dst affected src")
	}
}

func TestCloneHeaders_Empty(t *testing.T) {
	src := map[string]string{}
	dst := cloneHeaders(src)
	if dst == nil {
		t.Error("Expected non-nil empty map for empty input")
	}
	if len(dst) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(dst))
	}
}

// --- Tests for truncateStr ---

func TestTruncateStr_WithinLimit(t *testing.T) {
	input := "hello"
	result := truncateStr(input, 10)
	if result != input {
		t.Errorf("Expected %q, got %q", input, result)
	}
}

func TestTruncateStr_AtLimit(t *testing.T) {
	input := "hello"
	result := truncateStr(input, 5)
	if result != input {
		t.Errorf("Expected %q, got %q", input, result)
	}
}

func TestTruncateStr_ExceedsLimit(t *testing.T) {
	input := "hello world"
	result := truncateStr(input, 5)
	expected := "hello..."
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestTruncateStr_Empty(t *testing.T) {
	result := truncateStr("", 10)
	if result != "" {
		t.Errorf("Expected empty string, got %q", result)
	}
}

// --- Tests for printResults (output formatting) ---

func TestPrintResults_NoFindings(t *testing.T) {
	result := &model.ScanResult{
		Target:   "http://example.com",
		Findings: nil,
	}
	// Should not panic
	printResults(result, 100*time.Millisecond)
}

func TestPrintResults_WithFindings(t *testing.T) {
	result := &model.ScanResult{
		Target: "http://example.com",
		Findings: []model.Finding{
			{
				Type:        "reflected",
				Severity:    "high",
				Confidence:  0.85,
				URL:         "http://example.com/page?q=test",
				Parameter:   "q",
				Payload:     "<script>alert(1)</script>",
				Description: "Reflected XSS in query parameter",
				Contexts:    []string{"html_body"},
				RawRequest:  "GET /page?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
				RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>test</html>",
			},
		},
	}
	// Should not panic
	printResults(result, 250*time.Millisecond)
}

func TestPrintResults_WithWAF(t *testing.T) {
	result := &model.ScanResult{
		Target:   "http://example.com",
		Findings: nil,
		Stats: model.ScanStats{
			WAF: &model.WAFInfo{Name: "Cloudflare", Bypassed: true},
		},
	}
	// Should not panic
	printResults(result, 50*time.Millisecond)
}

func TestPrintResults_WithWAFNotBypassed(t *testing.T) {
	result := &model.ScanResult{
		Target:   "http://example.com",
		Findings: nil,
		Stats: model.ScanStats{
			WAF: &model.WAFInfo{Name: "AWS WAF", Bypassed: false},
		},
	}
	// Should not panic
	printResults(result, 50*time.Millisecond)
}
