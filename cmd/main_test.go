package main

import (
	"testing"
)

func TestParseHeaders_BlocksHost(t *testing.T) {
	headers := []string{"Host: evil.com"}
	result := parseHeaders(headers)
	if len(result) != 0 {
		t.Errorf("Expected Host header to be blocked, got: %v", result)
	}
}

func TestParseHeaders_BlocksContentLength(t *testing.T) {
	headers := []string{"Content-Length: 0"}
	result := parseHeaders(headers)
	if len(result) != 0 {
		t.Errorf("Expected Content-Length header to be blocked, got: %v", result)
	}
}

func TestParseHeaders_BlocksTransferEncoding(t *testing.T) {
	headers := []string{"Transfer-Encoding: chunked"}
	result := parseHeaders(headers)
	if len(result) != 0 {
		t.Errorf("Expected Transfer-Encoding header to be blocked, got: %v", result)
	}
}

func TestParseHeaders_AcceptsNormal(t *testing.T) {
	headers := []string{"X-Custom: value123"}
	result := parseHeaders(headers)
	if len(result) != 1 {
		t.Fatalf("Expected 1 header, got %d", len(result))
	}
	if result["X-Custom"] != "value123" {
		t.Errorf("Expected 'value123', got '%s'", result["X-Custom"])
	}
}

func TestParseHeaders_MixedBlockedAndAllowed(t *testing.T) {
	headers := []string{
		"Host: evil.com",
		"X-Custom: value",
		"Content-Length: 100",
		"Accept: */*",
	}
	result := parseHeaders(headers)
	if len(result) != 2 {
		t.Errorf("Expected 2 headers (Host and Content-Length blocked), got %d: %v", len(result), result)
	}
	if _, ok := result["X-Custom"]; !ok {
		t.Error("Expected X-Custom header to be present")
	}
	if _, ok := result["Accept"]; !ok {
		t.Error("Expected Accept header to be present")
	}
	if _, ok := result["Host"]; ok {
		t.Error("Expected Host header to be blocked")
	}
	if _, ok := result["Content-Length"]; ok {
		t.Error("Expected Content-Length header to be blocked")
	}
}

func TestParseHeaders_Empty(t *testing.T) {
	result := parseHeaders([]string{})
	if len(result) != 0 {
		t.Errorf("Expected empty map, got %v", result)
	}
}

func TestParseHeaders_Nil(t *testing.T) {
	result := parseHeaders(nil)
	if len(result) != 0 {
		t.Errorf("Expected empty map for nil input, got %v", result)
	}
}

func TestParseHeaders_InvalidFormat(t *testing.T) {
	headers := []string{"no-colon-here"}
	result := parseHeaders(headers)
	if len(result) != 0 {
		t.Errorf("Expected empty map for invalid format, got %v", result)
	}
}

func TestParseHeaders_EmptyValue(t *testing.T) {
	headers := []string{"X-Empty:"}
	result := parseHeaders(headers)
	if result["X-Empty"] != "" {
		t.Errorf("Expected empty value, got '%s'", result["X-Empty"])
	}
}

func TestParseHeaders_MultipleValues(t *testing.T) {
	headers := []string{"X-One: 1", "X-Two: 2", "X-Three: 3"}
	result := parseHeaders(headers)
	if len(result) != 3 {
		t.Errorf("Expected 3 headers, got %d", len(result))
	}
}

func TestParseHeaders_WhitespaceTrimming(t *testing.T) {
	headers := []string{"  X-Custom  :  value with spaces  "}
	result := parseHeaders(headers)
	if result["X-Custom"] != "value with spaces" {
		t.Errorf("Expected trimmed value, got '%s'", result["X-Custom"])
	}
}

func TestParseCookies_Valid(t *testing.T) {
	cookies := []string{"session=abc123"}
	result := parseCookies(cookies)
	if len(result) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(result))
	}
	if result[0].Name != "session" {
		t.Errorf("Expected name 'session', got '%s'", result[0].Name)
	}
	if result[0].Value != "abc123" {
		t.Errorf("Expected value 'abc123', got '%s'", result[0].Value)
	}
}

func TestParseCookies_InvalidFormat(t *testing.T) {
	cookies := []string{"noequalssign"}
	result := parseCookies(cookies)
	if len(result) != 0 {
		t.Errorf("Expected 0 cookies for invalid format, got %d", len(result))
	}
}

func TestParseCookies_EmptyValue(t *testing.T) {
	cookies := []string{"name="}
	result := parseCookies(cookies)
	if len(result) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(result))
	}
	if result[0].Value != "" {
		t.Errorf("Expected empty value, got '%s'", result[0].Value)
	}
}

func TestParseCookies_Multiple(t *testing.T) {
	cookies := []string{"a=1", "b=2", "c=3"}
	result := parseCookies(cookies)
	if len(result) != 3 {
		t.Errorf("Expected 3 cookies, got %d", len(result))
	}
}

func TestParseCookies_Empty(t *testing.T) {
	result := parseCookies([]string{})
	if len(result) != 0 {
		t.Errorf("Expected 0 cookies, got %d", len(result))
	}
}

func TestParseCookies_Nil(t *testing.T) {
	result := parseCookies(nil)
	if len(result) != 0 {
		t.Errorf("Expected 0 cookies for nil input, got %d", len(result))
	}
}

func TestParseCookies_ValueWithEquals(t *testing.T) {
	cookies := []string{"data=base64=="}
	result := parseCookies(cookies)
	if len(result) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(result))
	}
	if result[0].Value != "base64==" {
		t.Errorf("Expected 'base64==', got '%s'", result[0].Value)
	}
}

func TestBlockedHeaders_ContainsExpected(t *testing.T) {
	expected := []string{"Host", "Content-Length", "Transfer-Encoding"}
	for _, h := range expected {
		if !blockedHeaders[h] {
			t.Errorf("Expected '%s' to be in blockedHeaders", h)
		}
	}
}

func TestBlockedHeaders_DoesNotContainSafe(t *testing.T) {
	safe := []string{"User-Agent", "Accept", "X-Custom", "Authorization", "Cookie"}
	for _, h := range safe {
		if blockedHeaders[h] {
			t.Errorf("Expected '%s' to NOT be in blockedHeaders", h)
		}
	}
}

func TestMaxWorkersConstant(t *testing.T) {
	if maxWorkers != 1000 {
		t.Errorf("Expected maxWorkers=1000, got %d", maxWorkers)
	}
}

func TestDefaultMaxPayloadConstant(t *testing.T) {
	if defaultMaxPayload != 50 {
		t.Errorf("Expected defaultMaxPayload=50, got %d", defaultMaxPayload)
	}
}

func TestMinRateLimitConstant(t *testing.T) {
	if minRateLimit != 1 {
		t.Errorf("Expected minRateLimit=1, got %d", minRateLimit)
	}
}

func TestMinTimeoutConstant(t *testing.T) {
	if minTimeout != 1 {
		t.Errorf("Expected minTimeout=1, got %d", minTimeout)
	}
}
