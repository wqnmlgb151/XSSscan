package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfig_WorkersOverMax(t *testing.T) {
	cfg := &ScanConfig{Workers: 2000, RateLimit: 50, Timeout: 30, MaxPayload: 50}
	err := validateConfig(cfg)
	if err == nil {
		t.Error("Expected error for workers > max, got nil")
	}
}

func TestValidateConfig_WorkersAtMax(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: maxWorkers, RateLimit: 50, Timeout: 30, MaxPayload: 50}
	err := validateConfig(cfg)
	if err != nil {
		t.Errorf("Expected no error for workers at max, got: %v", err)
	}
}

func TestValidateConfig_RateLimitBelowMin(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: 10, RateLimit: 0, Timeout: 30, MaxPayload: 50}
	validateConfig(cfg)
	if cfg.RateLimit != minRateLimit {
		t.Errorf("Expected rate limit to be set to %d, got %d", minRateLimit, cfg.RateLimit)
	}
}

func TestValidateConfig_RateLimitNegative(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: 10, RateLimit: -5, Timeout: 30, MaxPayload: 50}
	validateConfig(cfg)
	if cfg.RateLimit != minRateLimit {
		t.Errorf("Expected rate limit to be set to %d, got %d", minRateLimit, cfg.RateLimit)
	}
}

func TestValidateConfig_TimeoutBelowMin(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: 10, RateLimit: 50, Timeout: 0, MaxPayload: 50}
	validateConfig(cfg)
	if cfg.Timeout != minTimeout {
		t.Errorf("Expected timeout to be set to %d, got %d", minTimeout, cfg.Timeout)
	}
}

func TestValidateConfig_TimeoutNegative(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: 10, RateLimit: 50, Timeout: -1, MaxPayload: 50}
	validateConfig(cfg)
	if cfg.Timeout != minTimeout {
		t.Errorf("Expected timeout to be set to %d, got %d", minTimeout, cfg.Timeout)
	}
}

func TestValidateConfig_DefaultMaxPayload(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: 10, RateLimit: 50, Timeout: 30, MaxPayload: 0}
	validateConfig(cfg)
	if cfg.MaxPayload != defaultMaxPayload {
		t.Errorf("Expected max payload to be set to %d, got %d", defaultMaxPayload, cfg.MaxPayload)
	}
}

func TestValidateConfig_NegativeMaxPayload(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com", Workers: 10, RateLimit: 50, Timeout: 30, MaxPayload: -1}
	validateConfig(cfg)
	if cfg.MaxPayload != defaultMaxPayload {
		t.Errorf("Expected max payload to be set to %d, got %d", defaultMaxPayload, cfg.MaxPayload)
	}
}

func TestValidateConfig_LoginURLHostMismatch(t *testing.T) {
	cfg := &ScanConfig{
		Workers: 10, RateLimit: 50, Timeout: 30, MaxPayload: 50,
		URL: "http://example.com/page",
		LoginURL: "http://evil.com/login",
	}
	err := validateConfig(cfg)
	if err == nil {
		t.Error("Expected error for login URL host mismatch, got nil")
	}
}

func TestValidateConfig_LoginURLHostMatch(t *testing.T) {
	cfg := &ScanConfig{
		Workers: 10, RateLimit: 50, Timeout: 30, MaxPayload: 50,
		URL: "http://example.com/page",
		LoginURL: "http://example.com/login",
	}
	err := validateConfig(cfg)
	if err != nil {
		t.Errorf("Expected no error for matching hosts, got: %v", err)
	}
}

func TestValidateConfig_NoLoginURL(t *testing.T) {
	cfg := &ScanConfig{
		Workers: 10, RateLimit: 50, Timeout: 30, MaxPayload: 50,
		URL: "http://example.com/page",
	}
	err := validateConfig(cfg)
	if err != nil {
		t.Errorf("Expected no error without login URL, got: %v", err)
	}
}

func TestValidateConfig_AllDefaults(t *testing.T) {
	cfg := &ScanConfig{URL: "http://example.com"}
	validateConfig(cfg)

	if cfg.RateLimit != minRateLimit {
		t.Errorf("Expected rate limit %d, got %d", minRateLimit, cfg.RateLimit)
	}
	if cfg.Timeout != minTimeout {
		t.Errorf("Expected timeout %d, got %d", minTimeout, cfg.Timeout)
	}
	if cfg.MaxPayload != defaultMaxPayload {
		t.Errorf("Expected max payload %d, got %d", defaultMaxPayload, cfg.MaxPayload)
	}
}

func TestLoadTargetsFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "targets.txt")
	content := "http://example.com/page1\nhttp://example.com/page2\n\n# comment\n  \nhttp://example.com/page3\n"
	os.WriteFile(f, []byte(content), 0644)

	urls, err := loadTargets(f)
	if err != nil {
		t.Fatalf("loadTargets failed: %v", err)
	}
	if len(urls) != 3 {
		t.Errorf("Expected 3 URLs, got %d: %v", len(urls), urls)
	}
	expected := []string{
		"http://example.com/page1",
		"http://example.com/page2",
		"http://example.com/page3",
	}
	for i, u := range urls {
		if u != expected[i] {
			t.Errorf("URL[%d]: expected %q, got %q", i, expected[i], u)
		}
	}
}

func TestLoadTargetsEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "empty.txt")
	os.WriteFile(f, []byte(""), 0644)

	urls, err := loadTargets(f)
	if err != nil {
		t.Fatalf("loadTargets failed: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("Expected 0 URLs, got %d", len(urls))
	}
}

func TestLoadTargetsNonExistent(t *testing.T) {
	_, err := loadTargets("/nonexistent/path/targets.txt")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestLoadTargetsSkipsComments(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "comments.txt")
	content := "# this is a comment\nhttp://a.com\n  # indented comment\nhttp://b.com\n"
	os.WriteFile(f, []byte(content), 0644)

	urls, err := loadTargets(f)
	if err != nil {
		t.Fatalf("loadTargets failed: %v", err)
	}
	if len(urls) != 2 {
		t.Errorf("Expected 2 URLs, got %d: %v", len(urls), urls)
	}
}

func TestCloneCookies(t *testing.T) {
	src := []*http.Cookie{
		{Name: "session", Value: "abc123"},
		{Name: "csrf", Value: "token456"},
	}
	dst := cloneCookies(src)
	if len(dst) != 2 {
		t.Fatalf("Expected 2 cookies, got %d", len(dst))
	}
	// Verify deep copy: modifying dst should not affect src
	dst[0].Value = "modified"
	if src[0].Value != "abc123" {
		t.Error("cloneCookies did not deep-copy: modifying dst affected src")
	}
}

func TestCloneCookiesNil(t *testing.T) {
	result := cloneCookies(nil)
	if result != nil {
		t.Errorf("Expected nil, got %v", result)
	}
}
