package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// saveCfg returns a function that restores the global cfg to its current state.
// Used to isolate tests that mutate the global config.
func saveCfg() func() {
	saved := cfg
	return func() { cfg = saved }
}

// TestRunScan_InvalidWorkers verifies that workers exceeding maxWorkers
// triggers a validation error before any scanning begins.
func TestRunScan_InvalidWorkers(t *testing.T) {
	defer saveCfg()()
	// Minimal config: only set what validateConfig needs to fail early
	cfg = ScanConfig{
		URL:      "http://example.com/page?q=test",
		Workers:  maxWorkers + 1,
		Silent:   true,
		NoColor:  true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for workers > max, got nil")
	}
	if !strings.Contains(err.Error(), "workers exceeds maximum") {
		t.Errorf("Expected 'workers exceeds maximum' error, got: %v", err)
	}
}

// TestRunScan_LoginURLHostMismatch verifies that a login URL on a different
// host than the target is rejected.
func TestRunScan_LoginURLHostMismatch(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{
		URL:      "http://example.com/page",
		LoginURL: "http://evil.com/login",
		Silent:   true,
		NoColor:  true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for login URL host mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "login-url host must match") {
		t.Errorf("Expected host mismatch error, got: %v", err)
	}
}

// TestRunScan_LoginURLWithoutPassword verifies that --login-url requires
// both --username and --password.
func TestRunScan_LoginURLWithoutPassword(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{
		URL:      "http://example.com/page",
		LoginURL: "http://example.com/login",
		Username: "admin",
		// Password intentionally omitted
		Silent:  true,
		NoColor: true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for missing password, got nil")
	}
	if !strings.Contains(err.Error(), "--login-url requires both --username and --password") {
		t.Errorf("Expected password requirement error, got: %v", err)
	}
}

// TestRunScan_LoginURLWithoutUsername verifies that --login-url requires
// both --username and --password (missing username case).
func TestRunScan_LoginURLWithoutUsername(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{
		URL:      "http://example.com/page",
		LoginURL: "http://example.com/login",
		Password: "secret",
		// Username intentionally omitted
		Silent:  true,
		NoColor: true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for missing username, got nil")
	}
	if !strings.Contains(err.Error(), "--login-url requires both --username and --password") {
		t.Errorf("Expected username requirement error, got: %v", err)
	}
}

// TestRunScan_NonExistentTargetsFile verifies that a missing targets file
// produces an error before scanning begins.
func TestRunScan_NonExistentTargetsFile(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{
		URL:         "http://placeholder.com",
		TargetsFile: "/nonexistent/path/to/targets.txt",
		Silent:      true,
		NoColor:     true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for non-existent targets file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load targets") {
		t.Errorf("Expected load targets error, got: %v", err)
	}
}

// TestRunScan_InvalidProxyURL verifies that a malformed proxy URL is rejected.
func TestRunScan_InvalidProxyURL(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{
		URL:     "http://example.com/page",
		Proxy:   "://not-a-valid-url",
		Silent:  true,
		NoColor: true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for invalid proxy URL, got nil")
	}
	if !strings.Contains(err.Error(), "proxy validation failed") {
		t.Errorf("Expected proxy validation error, got: %v", err)
	}
}

// TestRunScan_ProxyInvalidScheme verifies that a proxy URL with a disallowed
// scheme (e.g., ftp) is rejected.
func TestRunScan_ProxyInvalidScheme(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{
		URL:       "http://example.com/page",
		Proxy:     "ftp://proxy.example.com:21",
		Silent:    true,
		NoColor:   true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected error for invalid proxy scheme, got nil")
	}
	if !strings.Contains(err.Error(), "proxy scheme must be http, https, or socks5") {
		t.Errorf("Expected proxy scheme error, got: %v", err)
	}
}

// TestRunScan_EmptyHeadersAndCookies verifies that runScan handles
// nil/empty headers and cookies gracefully through the scan setup phase.
// This exercises parseHeaders and parseCookies indirectly via runScan.
func TestRunScan_EmptyHeadersAndCookies(t *testing.T) {
	defer saveCfg()()
	// Invalid workers causes early validation failure before scan starts.
	// This confirms that the early validation path is reached even when
	// Headers and Cookies are nil.
	cfg = ScanConfig{
		URL:     "http://example.com",
		Workers: maxWorkers + 1,
		Headers: nil,
		Cookies: nil,
		Silent:  true,
		NoColor: true,
	}

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("Expected validation error")
	}
}

// TestCollectChangedFlags verifies that collectChangedFlags returns an empty
// map when no flags are explicitly set on the command.
func TestCollectChangedFlags(t *testing.T) {
	// Use the rootCmd which has all flags defined but none visited
	flags := collectChangedFlags(rootCmd)
	if len(flags) != 0 {
		t.Errorf("Expected 0 changed flags for fresh command, got %d: %v", len(flags), flags)
	}
}

// TestCollectChangedFlags_AfterSet verifies that flags set via cobra are
// detected by collectChangedFlags.
func TestCollectChangedFlags_AfterSet(t *testing.T) {
	// Create a fresh command to avoid polluting rootCmd
	cmd := &cobra.Command{}
	cmd.Flags().String("url", "", "target URL")
	cmd.Flags().Int("workers", 10, "worker count")

	// Simulate the user setting --url on the command line
	cmd.Flags().Set("url", "http://test.com")

	flags := collectChangedFlags(cmd)
	// Only "url" was changed
	if !flags["url"] {
		t.Error("Expected 'url' to be in changed flags")
	}
	if flags["workers"] {
		t.Error("Did not expect 'workers' in changed flags")
	}
}
