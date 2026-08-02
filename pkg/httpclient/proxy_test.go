package httpclient

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestProxyValidate_EmptyURL(t *testing.T) {
	p := &ProxyConfig{URL: ""}
	err := p.Validate()
	if err == nil {
		t.Error("Expected error for empty URL, got nil")
	}
}

func TestProxyValidate_InvalidURL(t *testing.T) {
	p := &ProxyConfig{URL: "://bad url with spaces"}
	err := p.Validate()
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestProxyValidate_InvalidSchemes(t *testing.T) {
	invalid := []string{
		"ftp://127.0.0.1:8080",
		"file:///etc/passwd",
		"gopher://example.com",
		"ssh://127.0.0.1:22",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			p := &ProxyConfig{URL: raw}
			if err := p.Validate(); err == nil {
				t.Errorf("Expected error for URL %q, got nil", raw)
			}
		})
	}
}

func TestProxyValidate_ValidSchemes(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	valid := []string{
		"http://127.0.0.1:8080",
		"https://127.0.0.1:8443",
		"socks5://127.0.0.1:1080",
	}
	for _, raw := range valid {
		t.Run(raw, func(t *testing.T) {
			p := &ProxyConfig{URL: raw}
			if err := p.Validate(); err != nil {
				t.Errorf("Expected no error for URL %q, got: %v", raw, err)
			}
		})
	}
}

func TestProxyValidate_NoHost(t *testing.T) {
	p := &ProxyConfig{URL: "http://"}
	err := p.Validate()
	if err == nil {
		t.Error("Expected error for URL with no host, got nil")
	}
}

func TestProxyValidate_SSRFBlocked(t *testing.T) {
	ssrfguard.AllowPrivate = false
	defer func() { ssrfguard.AllowPrivate = false }()

	p := &ProxyConfig{URL: "http://127.0.0.1:8080"}
	err := p.Validate()
	if err == nil {
		t.Error("Expected SSRF block for private IP, got nil")
	}
}

func TestProxyValidate_SSRFAllowed(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	p := &ProxyConfig{URL: "http://127.0.0.1:8080"}
	if err := p.Validate(); err != nil {
		t.Errorf("Expected no error with AllowPrivate=true, got: %v", err)
	}
}

func TestProxyValidate_LoopbackBlocked(t *testing.T) {
	ssrfguard.AllowPrivate = false
	defer func() { ssrfguard.AllowPrivate = false }()

	p := &ProxyConfig{URL: "http://169.254.169.254:8080"}
	err := p.Validate()
	if err == nil {
		t.Error("Expected SSRF block for link-local IP, got nil")
	}
}

func TestApplyToTransport_SetsProxy(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	p := &ProxyConfig{URL: "http://127.0.0.1:8080"}
	transport := &http.Transport{}
	if err := p.ApplyToTransport(transport); err != nil {
		t.Fatalf("ApplyToTransport failed: %v", err)
	}
	if transport.Proxy == nil {
		t.Fatal("Expected transport.Proxy to be set")
	}
	// Verify proxy URL is correct
	proxyURL, _ := transport.Proxy(nil)
	expected, _ := url.Parse("http://127.0.0.1:8080")
	if proxyURL.Host != expected.Host {
		t.Errorf("Expected proxy host %q, got %q", expected.Host, proxyURL.Host)
	}
}

func TestApplyToTransport_InvalidURL(t *testing.T) {
	p := &ProxyConfig{URL: "://bad"}
	transport := &http.Transport{}
	err := p.ApplyToTransport(transport)
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestProxyAuthHeader_WithCredentials(t *testing.T) {
	p := &ProxyConfig{Username: "alice", Password: "secret"}
	header, ok := p.ProxyAuthHeader()
	if !ok {
		t.Fatal("Expected ok=true with credentials set")
	}
	expected := "Basic " + basicAuth("alice", "secret")
	if header != expected {
		t.Errorf("Expected %q, got %q", expected, header)
	}
}

func TestProxyAuthHeader_WithoutCredentials(t *testing.T) {
	p := &ProxyConfig{}
	_, ok := p.ProxyAuthHeader()
	if ok {
		t.Error("Expected ok=false without credentials")
	}
}

func TestProxyAuthHeader_EmptyUsername(t *testing.T) {
	p := &ProxyConfig{Username: "", Password: "secret"}
	_, ok := p.ProxyAuthHeader()
	if ok {
		t.Error("Expected ok=false with empty username")
	}
}

func TestBasicAuth_Encoding(t *testing.T) {
	result := basicAuth("user", "pass")
	expected := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestBasicAuth_EmptyPassword(t *testing.T) {
	result := basicAuth("admin", "")
	expected := base64.StdEncoding.EncodeToString([]byte("admin:"))
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestBasicAuth_SpecialChars(t *testing.T) {
	result := basicAuth("user@domain.com", "p@ss:w0rd!")
	expected := base64.StdEncoding.EncodeToString([]byte("user@domain.com:p@ss:w0rd!"))
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestNewClient_WithProxy(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	proxy := &ProxyConfig{URL: "http://127.0.0.1:8080"}
	client := NewClient(0, proxy)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.Jar == nil {
		t.Error("Expected cookie jar to be set")
	}
	// Verify proxy is configured on transport
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected *http.Transport")
	}
	if transport.Proxy == nil {
		t.Error("Expected transport.Proxy to be set")
	}
}

func TestNewClient_WithoutProxy(t *testing.T) {
	client := NewClient(0, nil)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.Jar == nil {
		t.Error("Expected cookie jar to be set")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected *http.Transport")
	}
	if transport.Proxy != nil {
		t.Error("Expected transport.Proxy to be nil without proxy config")
	}
}

func TestNewClient_ProxyInsecure(t *testing.T) {
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = false }()

	proxy := &ProxyConfig{URL: "https://127.0.0.1:8443", Insecure: true}
	client := NewClient(0, proxy)
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("Expected TLSClientConfig to be set")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify=true")
	}
}
