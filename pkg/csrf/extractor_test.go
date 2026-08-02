package csrf

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExtractCSRF_FromFormField(t *testing.T) {
	html := `<!DOCTYPE html>
<html><body>
<form action="/login" method="POST">
<input type="hidden" name="csrf_token" value="abc123xyz">
<input type="text" name="username">
<input type="password" name="password">
</form>
</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}))
	defer server.Close()

	extractor := NewExtractor(server.Client())
	token, err := extractor.ExtractCSRF(server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if token == nil {
		t.Fatal("Expected token, got nil")
	}
	if token.Value != "abc123xyz" {
		t.Errorf("Expected value abc123xyz, got %s", token.Value)
	}
	if token.FieldName != "csrf_token" {
		t.Errorf("Expected field name csrf_token, got %s", token.FieldName)
	}
	if token.Source != "form" {
		t.Errorf("Expected source form, got %s", token.Source)
	}
}

func TestExtractCSRF_FromMetaTag(t *testing.T) {
	html := `<!DOCTYPE html>
<html><head>
<meta name="csrf-token" content="meta-token-456">
</head><body><form></form></body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}))
	defer server.Close()

	extractor := NewExtractor(server.Client())
	token, err := extractor.ExtractCSRF(server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if token == nil || token.Value != "meta-token-456" {
		t.Errorf("Expected meta-token-456, got %v", token)
	}
	if token.Source != "meta" {
		t.Errorf("Expected source meta, got %s", token.Source)
	}
}

func TestExtractCSRF_FromCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: "cookie-token-789"})
		w.Write([]byte(`<html><body><form></form></body></html>`))
	}))
	defer server.Close()

	jar, _ := cookiejar.New(nil)
	client := server.Client()
	client.Jar = jar

	extractor := NewExtractor(client)
	token, err := extractor.ExtractCSRF(server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if token == nil || token.Value != "cookie-token-789" {
		t.Errorf("Expected cookie-token-789, got %v", token)
	}
	if token.Source != "cookie" {
		t.Errorf("Expected source cookie, got %s", token.Source)
	}
}

func TestExtractCSRF_NoToken(t *testing.T) {
	html := `<!DOCTYPE html><html><body><p>No forms here</p></body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}))
	defer server.Close()

	extractor := NewExtractor(server.Client())
	_, err := extractor.ExtractCSRF(server.URL)
	if err == nil {
		t.Fatal("Expected error when no token found")
	}
	if !strings.Contains(err.Error(), "no CSRF token found") {
		t.Errorf("Expected 'no CSRF token found', got: %v", err)
	}
}

func TestExtractCSRF_PrioritizesFormOverMeta(t *testing.T) {
	html := `<!DOCTYPE html>
<html><head><meta name="csrf-token" content="meta-val"></head>
<body><form><input type="hidden" name="_token" value="form-val"></form></body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}))
	defer server.Close()

	extractor := NewExtractor(server.Client())
	token, err := extractor.ExtractCSRF(server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if token.Source != "form" {
		t.Errorf("Expected form to take priority, got source: %s", token.Source)
	}
	if token.Value != "form-val" {
		t.Errorf("Expected form-val, got %s", token.Value)
	}
}

func TestIsCSRFFieldName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"csrf_token", true},
		{"_token", true},
		{"authenticity_token", true},
		{"csrfmiddlewaretoken", true},
		{"__RequestVerificationToken", true},
		{"ASPNet_CSRF", true},
		{"some_random_field", false},
		{"username", false},
		{"email", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCSRFFieldName(tt.name); got != tt.expected {
				t.Errorf("isCSRFFieldName(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestExtractCSRF_InvalidURL(t *testing.T) {
	extractor := NewExtractor(&http.Client{})
	_, err := extractor.ExtractCSRF("http://[invalid")
	if err == nil {
		t.Fatal("Expected error for invalid URL")
	}
}

// Verify cookie jar integration works end-to-end.
func TestExtractCSRF_CookieJarIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		http.SetCookie(w, &http.Cookie{Name: "csrf_cookie", Value: "jar-value"})
		w.Write([]byte(`<html><body></body></html>`))
	}))
	defer server.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "csrf_cookie", Value: "jar-value"}})

	extractor := NewExtractor(client)
	token, err := extractor.ExtractCSRF(server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if token == nil || token.Value != "jar-value" {
		t.Errorf("Expected jar-value, got %v", token)
	}
}
