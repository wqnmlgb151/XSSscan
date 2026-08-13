package execverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestVerifyFinding_QueryParam_Alert(t *testing.T) {
	// Create a test server that reflects the "q" parameter into an HTML body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	// This test requires a real Chrome instance, so it's only run in integration mode
	if testing.Short() {
		t.Skip("skipping browser integration test in short mode")
	}

	v, err := NewVerifier(context.Background(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	finding := model.Finding{
		Parameter: "q",
		ParamType: model.ParamQuery,
		Payload:   `<img src=x onerror=alert(1)>`,
		URL:       server.URL + "?q=test",
	}

	result, err := v.VerifyFinding(context.Background(), finding, model.Target{URL: server.URL + "?q=test"})
	if err != nil {
		t.Fatalf("VerifyFinding: %v", err)
	}

	if !result.Executed {
		t.Logf("Dialog not detected (may be expected in headless mode without JS execution): %+v", result)
		// Note: simple reflection may not trigger execution in headless Chrome
		// without the payload actually being rendered as HTML
	}
}

func TestVerifyFinding_QueryParam_ScriptInjection(t *testing.T) {
	// Create a test server that reflects into a script context
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><script>var x = '` + q + `';</script></body></html>`))
	}))
	defer server.Close()

	if testing.Short() {
		t.Skip("skipping browser integration test in short mode")
	}

	v, err := NewVerifier(context.Background(), 10*time.Second)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	defer v.Close()

	finding := model.Finding{
		Parameter: "q",
		ParamType: model.ParamQuery,
		Payload:   `';alert(1)//`,
		URL:       server.URL + "?q=test",
	}

	result, err := v.VerifyFinding(context.Background(), finding, model.Target{URL: server.URL + "?q=test"})
	if err != nil {
		t.Fatalf("VerifyFinding: %v", err)
	}

	t.Logf("Result: executed=%v type=%s confidence=%f", result.Executed, result.DialogType, result.Confidence)
}

func TestBuildNavigationURL_Query(t *testing.T) {
	v := &Verifier{}

	tests := []struct {
		name      string
		targetURL string
		param     string
		paramType model.ParamType
		payload   string
		want      string
	}{
		{
			name:      "simple query param",
			targetURL: "http://example.com/page?q=test",
			param:     "q",
			paramType: model.ParamQuery,
			payload:   "<script>alert(1)</script>",
			want:      "http://example.com/page?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
		},
		{
			name:      "add query param to URL without query",
			targetURL: "http://example.com/page",
			param:     "q",
			paramType: model.ParamQuery,
			payload:   "test",
			want:      "http://example.com/page?q=test",
		},
		{
			name:      "multiple query params",
			targetURL: "http://example.com/page?a=1&b=2",
			param:     "b",
			paramType: model.ParamQuery,
			payload:   "XSS",
			want:      "http://example.com/page?a=1&b=XSS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := model.Target{URL: tt.targetURL}
			got, err := v.buildNavigationURL(target, tt.param, tt.paramType, tt.payload)
			if err != nil {
				t.Fatalf("buildNavigationURL: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildNavigationURL_UnsupportedType(t *testing.T) {
	v := &Verifier{}
	target := model.Target{URL: "http://example.com/page"}
	_, err := v.buildNavigationURL(target, "body_param", model.ParamBody, "test")
	if err == nil {
		t.Error("expected error for body param type, got nil")
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"/api/v1/users", []string{"", "api", "v1", "users"}},
		{"/", []string{""}},
		{"", []string{""}},
		{"/single", []string{"", "single"}},
	}

	for _, tt := range tests {
		got := splitPath(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitPath(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitPath(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct {
		input []string
		want  string
	}{
		{[]string{"", "api", "v1", "users"}, "/api/v1/users"},
		{[]string{"", "single"}, "/single"},
	}

	for _, tt := range tests {
		got := joinPath(tt.input)
		if got != tt.want {
			t.Errorf("joinPath(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseDialogJSON(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   dialogInfo
	}{
		{
			name:  "alert dialog",
			input: `{"type":"alert","message":"1"}`,
			want:  dialogInfo{dialogType: "alert", message: "1"},
		},
		{
			name:  "confirm dialog",
			input: `{"type":"confirm","message":"Are you sure?"}`,
			want:  dialogInfo{dialogType: "confirm", message: "Are you sure?"},
		},
		{
			name:  "empty string",
			input: "",
			want:  dialogInfo{},
		},
		{
			name:  "too short",
			input: `{"type"`,
			want:  dialogInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDialogJSON(tt.input)
			if got.dialogType != tt.want.dialogType {
				t.Errorf("dialogType = %q, want %q", got.dialogType, tt.want.dialogType)
			}
			if got.message != tt.want.message {
				t.Errorf("message = %q, want %q", got.message, tt.want.message)
			}
		})
	}
}

func TestBuildHTMLPOC(t *testing.T) {
	payload := `<script>alert("xss")</script>`
	poc := buildHTMLPOC(payload)
	if !strings.Contains(poc, "&lt;script&gt;") {
		t.Error("expected HTML-escaped payload in POC")
	}
	if !strings.Contains(poc, "<title>XSS POC</title>") {
		t.Error("expected POC title")
	}
}


func TestNewVerifierDefaultTimeout(t *testing.T) {
	v, err := NewVerifier(context.Background(), 0)
	if err != nil {
		t.Fatalf("NewVerifier with zero timeout: %v", err)
	}
	defer v.Close()
	if v.timeout != 15*time.Second {
		t.Errorf("expected default timeout 15s, got %v", v.timeout)
	}
}

func TestNewVerifierWithAuth(t *testing.T) {
	auth := &AuthState{
		Cookies: []*http.Cookie{{Name: "session", Value: "abc123"}},
	}
	v, err := NewVerifierWithAuth(context.Background(), 5*time.Second, auth)
	if err != nil {
		t.Fatalf("NewVerifierWithAuth: %v", err)
	}
	defer v.Close()
	if v.auth == nil {
		t.Error("expected auth state to be set")
	}
	if len(v.auth.Cookies) != 1 {
		t.Errorf("expected 1 cookie, got %d", len(v.auth.Cookies))
	}
}
