package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	content := `
url: "http://example.com/page?q=test"
workers: 20
rate-limit: 100
timeout: 60
waf-bypass: true
confidence: 0.70
format: "markdown"
headers:
  - "Authorization: Bearer token123"
  - "X-Custom: value"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fc, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if fc.URL != "http://example.com/page?q=test" {
		t.Errorf("URL: got %q", fc.URL)
	}
	if fc.Workers != 20 {
		t.Errorf("Workers: got %d", fc.Workers)
	}
	if fc.RateLimit != 100 {
		t.Errorf("RateLimit: got %d", fc.RateLimit)
	}
	if fc.Timeout != 60 {
		t.Errorf("Timeout: got %d", fc.Timeout)
	}
	if !fc.WAFBypass {
		t.Error("WAFBypass: expected true")
	}
	if fc.ConfidenceMin != 0.70 {
		t.Errorf("ConfidenceMin: got %f", fc.ConfidenceMin)
	}
	if fc.Format != "markdown" {
		t.Errorf("Format: got %q", fc.Format)
	}
	if len(fc.Headers) != 2 {
		t.Errorf("Headers: got %d entries", len(fc.Headers))
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")

	if err := os.WriteFile(path, []byte("{{invalid yaml: ["), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadConfig_NotExist(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yml")
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestFileConfig_ApplyTo_OnlyFillsUnchanged(t *testing.T) {
	fc := &FileConfig{
		URL:           "http://from-file.com",
		Workers:       50,
		RateLimit:     200,
		WAFBypass:     true,
		ConfidenceMin: 0.80,
	}

	cfg := &ScanConfig{
		URL:           "http://from-cli.com",
		Workers:       10,
		RateLimit:     200, // same as file — but flag not set, so file wins
		WAFBypass:     false,
		ConfidenceMin: 0.60,
	}

	// Simulate CLI flags that were explicitly set
	flags := map[string]bool{
		"url": true, // URL was set via CLI — file should NOT override
	}

	fc.ApplyTo(cfg, flags)

	// URL: CLI flag was set, so file value should not override
	if cfg.URL != "http://from-cli.com" {
		t.Errorf("URL should remain CLI value, got %q", cfg.URL)
	}
	// Workers: no CLI flag, so file value should apply
	if cfg.Workers != 50 {
		t.Errorf("Workers should be from file, got %d", cfg.Workers)
	}
	// RateLimit: no CLI flag, file value applies (even if same)
	if cfg.RateLimit != 200 {
		t.Errorf("RateLimit: got %d", cfg.RateLimit)
	}
	// WAFBypass: no CLI flag, file value applies
	if !cfg.WAFBypass {
		t.Error("WAFBypass should be true from file")
	}
	// ConfidenceMin: no CLI flag, file value applies
	if cfg.ConfidenceMin != 0.80 {
		t.Errorf("ConfidenceMin: got %f", cfg.ConfidenceMin)
	}
}

func TestLoadConfig_WithJWT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	content := `
url: "http://example.com/api"
jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fc, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if fc.JWT == "" {
		t.Error("JWT should be loaded from config")
	}
	if fc.URL != "http://example.com/api" {
		t.Errorf("URL: got %q", fc.URL)
	}
}

func TestFileConfig_ApplyTo_JWT(t *testing.T) {
	fc := &FileConfig{
		JWT: "eyJhbGciOiJIUzI1NiJ9.test",
	}
	cfg := &ScanConfig{}
	fc.ApplyTo(cfg, map[string]bool{})

	if cfg.JWT != "eyJhbGciOiJIUzI1NiJ9.test" {
		t.Errorf("JWT should be from file, got %q", cfg.JWT)
	}

	// Now test that CLI flag overrides
	cfg2 := &ScanConfig{JWT: "cli-token"}
	fc.ApplyTo(cfg2, map[string]bool{"jwt": true})
	if cfg2.JWT != "cli-token" {
		t.Error("CLI JWT should override file config")
	}
}

func TestFileConfig_ApplyTo_AllFilledWhenNoFlags(t *testing.T) {
	fc := &FileConfig{
		Method:        "POST",
		Output:        "report.json",
		Format:        "json",
		Workers:       5,
		RateLimit:     30,
		Timeout:       45,
		MaxPayload:    25,
		Callback:      "http://callback.example.com",
		Verbose:       true,
		Headless:      true,
		RandomUA:      true,
		AdaptiveRate:  true,
		PayloadPreset: "full",
	}

	cfg := &ScanConfig{}
	fc.ApplyTo(cfg, map[string]bool{}) // no CLI flags set

	if cfg.Method != "POST" {
		t.Errorf("Method: got %q", cfg.Method)
	}
	if cfg.Output != "report.json" {
		t.Errorf("Output: got %q", cfg.Output)
	}
	if cfg.Format != "json" {
		t.Errorf("Format: got %q", cfg.Format)
	}
	if cfg.Workers != 5 {
		t.Errorf("Workers: got %d", cfg.Workers)
	}
	if cfg.RateLimit != 30 {
		t.Errorf("RateLimit: got %d", cfg.RateLimit)
	}
	if cfg.Timeout != 45 {
		t.Errorf("Timeout: got %d", cfg.Timeout)
	}
	if cfg.MaxPayload != 25 {
		t.Errorf("MaxPayload: got %d", cfg.MaxPayload)
	}
	if cfg.Callback != "http://callback.example.com" {
		t.Errorf("Callback: got %q", cfg.Callback)
	}
	if !cfg.Verbose {
		t.Error("Verbose: expected true")
	}
	if !cfg.Headless {
		t.Error("Headless: expected true")
	}
	if !cfg.RandomUA {
		t.Error("RandomUA: expected true")
	}
	if !cfg.AdaptiveRate {
		t.Error("AdaptiveRate: expected true")
	}
	if cfg.PayloadPreset != "full" {
		t.Errorf("PayloadPreset: got %q", cfg.PayloadPreset)
	}
}
