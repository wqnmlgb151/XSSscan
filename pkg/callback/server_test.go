package callback

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServer_ReceivesCallback(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	baseURL := srv.BaseURL()

	// Simulate a blind XSS callback
	resp, err := http.Get(baseURL + "/c?cookie=test123&url=http://target.com")
	if err != nil {
		t.Fatalf("Callback request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	// Give server time to process
	time.Sleep(100 * time.Millisecond)

	callbacks := srv.Callbacks()
	if len(callbacks) != 1 {
		t.Fatalf("Expected 1 callback, got %d", len(callbacks))
	}

	cb := callbacks[0]
	if cb.Query != "cookie=test123&url=http://target.com" {
		t.Errorf("Expected query string, got: %s", cb.Query)
	}
	if cb.Method != http.MethodGet {
		t.Errorf("Expected GET method, got: %s", cb.Method)
	}
}

func TestServer_POSTCallback(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	baseURL := srv.BaseURL()

	// Simulate POST callback (e.g., fetch POST exfil)
	resp, err := http.Post(baseURL+"/data", "application/x-www-form-urlencoded",
		strings.NewReader("secret=data&csrf=token123"))
	if err != nil {
		t.Fatalf("POST callback failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	time.Sleep(100 * time.Millisecond)

	callbacks := srv.Callbacks()
	if len(callbacks) != 1 {
		t.Fatalf("Expected 1 callback, got %d", len(callbacks))
	}

	cb := callbacks[0]
	if cb.Method != http.MethodPost {
		t.Errorf("Expected POST, got %s", cb.Method)
	}
	if !strings.Contains(cb.Body, "secret=data") {
		t.Errorf("Expected body to contain 'secret=data', got: %s", cb.Body)
	}
}

func TestServer_WaitFor(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	baseURL := srv.BaseURL()

	// Send callback after a short delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		http.Get(baseURL + "/delayed")
	}()

	// Wait for callback with 5 second timeout
	callbacks := srv.WaitFor(1, 5*time.Second)
	if len(callbacks) != 1 {
		t.Fatalf("Expected 1 callback from WaitFor, got %d", len(callbacks))
	}
}

func TestServer_WaitForTimeout(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	// No callbacks sent — should return empty after timeout
	callbacks := srv.WaitFor(1, 300*time.Millisecond)
	if len(callbacks) != 0 {
		t.Fatalf("Expected 0 callbacks (timeout), got %d", len(callbacks))
	}
}

func TestServer_Reset(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	baseURL := srv.BaseURL()

	http.Get(baseURL + "/test1")
	time.Sleep(100 * time.Millisecond)

	if srv.Count() != 1 {
		t.Fatalf("Expected 1 callback before reset, got %d", srv.Count())
	}

	srv.Reset()
	if srv.Count() != 0 {
		t.Fatalf("Expected 0 callbacks after reset, got %d", srv.Count())
	}
}

func TestServer_HealthEndpoint(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	baseURL := srv.BaseURL()

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestServer_CORSHeaders(t *testing.T) {
	srv := NewServer("127.0.0.1:0")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer srv.Stop()

	baseURL := srv.BaseURL()

	resp, err := http.Get(baseURL + "/test")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao != "*" {
		t.Errorf("Expected CORS header *, got: %s", acao)
	}
}
