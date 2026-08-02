package scanner

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestBuildRawRequest_ContainsMethodAndURL(t *testing.T) {
	target := model.Target{
		URL:    "http://example.com/search?q=test",
		Method: "GET",
	}

	result := buildRawRequest(target)
	// HTTP/1.1 origin-form: request-target is path + query, Host header carries authority
	if !strings.Contains(result, "GET /search?q=test HTTP/1.1") {
		t.Errorf("Expected origin-form request line, got:\n%s", result)
	}
	if !strings.Contains(result, "Host: example.com") {
		t.Errorf("Expected Host header, got:\n%s", result)
	}
}

func TestBuildRawRequest_ContainsHeaders(t *testing.T) {
	target := model.Target{
		URL:    "http://example.com/page",
		Method: "GET",
		Headers: map[string]string{
			"User-Agent": "xsscan-test",
			"X-Custom":   "value123",
		},
	}

	result := buildRawRequest(target)
	if !strings.Contains(result, "User-Agent: xsscan-test") {
		t.Errorf("Expected User-Agent header, got:\n%s", result)
	}
	if !strings.Contains(result, "X-Custom: value123") {
		t.Errorf("Expected X-Custom header, got:\n%s", result)
	}
}

func TestBuildRawRequest_ContainsBody(t *testing.T) {
	body := `{"name":"test"}`
	target := model.Target{
		URL:    "http://example.com/api",
		Method: "POST",
		Body:   body,
	}

	result := buildRawRequest(target)
	if !strings.Contains(result, "Content-Length: 15") {
		t.Errorf("Expected Content-Length: 15, got:\n%s", result)
	}
	if !strings.Contains(result, body) {
		t.Errorf("Expected body in raw request, got:\n%s", result)
	}
}

func TestBuildRawRequest_POSTWithEmptyBody(t *testing.T) {
	target := model.Target{
		URL:    "http://example.com/api",
		Method: "POST",
	}

	result := buildRawRequest(target)
	if strings.Contains(result, "Content-Length") {
		t.Errorf("Expected no Content-Length for empty body, got:\n%s", result)
	}
}

func TestCaptureRawResponse_ContainsStatusLine(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	result := captureRawResponse(resp, []byte("OK"))
	if !strings.Contains(result, "HTTP/1.1 200") {
		t.Errorf("Expected status line, got:\n%s", result)
	}
}

func TestCaptureRawResponse_ShortBodyNotTruncated(t *testing.T) {
	body := []byte("<html>Hello World</html>")
	resp := &http.Response{
		Header: http.Header{},
	}

	result := captureRawResponse(resp, body)
	if !strings.Contains(result, "<html>Hello World</html>") {
		t.Errorf("Expected full body, got:\n%s", result)
	}
	if strings.Contains(result, "[truncated]") {
		t.Errorf("Short body should not be truncated, got:\n%s", result)
	}
}

func TestCaptureRawResponse_TruncatedAt4KB(t *testing.T) {
	body := make([]byte, 5000)
	for i := range body {
		body[i] = 'A'
	}
	resp := &http.Response{
		Header: http.Header{},
	}

	result := captureRawResponse(resp, body)
	if !strings.Contains(result, "... [truncated]") {
		t.Errorf("Expected truncation marker for 5KB body, got:\n%s", result)
	}
	bodyStart := strings.Index(result, "\r\n\r\n") + 4
	bodyPortion := result[bodyStart:]
	expectedLen := rawResponseCap + len("\n... [truncated]")
	if len(bodyPortion) != expectedLen {
		t.Errorf("Expected truncated body length %d, got %d", expectedLen, len(bodyPortion))
	}
}

func TestCaptureRawResponse_ContainsHeaders(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"text/html"},
			"X-Custom":     []string{"value"},
		},
	}

	result := captureRawResponse(resp, []byte("OK"))
	if !strings.Contains(result, "Content-Type: text/html") {
		t.Errorf("Expected Content-Type header, got:\n%s", result)
	}
	if !strings.Contains(result, "X-Custom: value") {
		t.Errorf("Expected X-Custom header, got:\n%s", result)
	}
}

func TestCaptureRawResponse_EmptyBody(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
	}

	result := captureRawResponse(resp, []byte{})
	parts := strings.SplitN(result, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Errorf("Expected header/body separator, got:\n%s", result)
	}
	if parts[1] != "" {
		t.Errorf("Expected empty body, got: %q", parts[1])
	}
}
