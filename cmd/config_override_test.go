package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestApplyTo_FileFillsZeroValues verifies that when no CLI flags are set,
// every non-zero field from the file config overwrites the zero-value ScanConfig.
func TestApplyTo_FileFillsZeroValues(t *testing.T) {
	fc := &FileConfig{
		URL:             "http://from-file.com/page",
		Method:          "POST",
		Headers:         []string{"Authorization: Bearer file-token"},
		Body:            "data=from-file",
		Cookies:         []string{"session=file123"},
		Output:          "report.json",
		Format:          "markdown",
		Workers:         25,
		RateLimit:       75,
		Timeout:         45,
		MaxPayload:      30,
		Callback:        "http://callback.example.com",
		Verbose:         true,
		LoginURL:        "http://from-file.com/login",
		Username:        "fileuser",
		Password:        "filepass",
		TestHPP:         true,
		WAFBypass:       true,
		ConfidenceMin:   0.85,
		AllowPrivate:    true,
		Proxy:           "http://proxy.example.com:8080",
		ProxyUsername:   "proxyuser",
		ProxyPassword:   "proxypass",
		ProxyInsecure:   true,
		Crawl:           true,
		CrawlDepth:      5,
		CrawlMaxPages:   100,
		TargetsFile:     "/tmp/targets.txt",
		RandomUA:        true,
		AdaptiveRate:    true,
		PayloadPreset:   "full",
		PayloadWordlist: "/tmp/wordlist.txt",
		Headless:        true,
		JWT:             "file.jwt.token",
	}

	cfg := &ScanConfig{} // all zero values
	fc.ApplyTo(cfg, map[string]bool{})

	if cfg.URL != "http://from-file.com/page" {
		t.Errorf("URL: got %q", cfg.URL)
	}
	if cfg.Method != "POST" {
		t.Errorf("Method: got %q", cfg.Method)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0] != "Authorization: Bearer file-token" {
		t.Errorf("Headers: got %v", cfg.Headers)
	}
	if cfg.Body != "data=from-file" {
		t.Errorf("Body: got %q", cfg.Body)
	}
	if len(cfg.Cookies) != 1 || cfg.Cookies[0] != "session=file123" {
		t.Errorf("Cookies: got %v", cfg.Cookies)
	}
	if cfg.Output != "report.json" {
		t.Errorf("Output: got %q", cfg.Output)
	}
	if cfg.Format != "markdown" {
		t.Errorf("Format: got %q", cfg.Format)
	}
	if cfg.Workers != 25 {
		t.Errorf("Workers: got %d", cfg.Workers)
	}
	if cfg.RateLimit != 75 {
		t.Errorf("RateLimit: got %d", cfg.RateLimit)
	}
	if cfg.Timeout != 45 {
		t.Errorf("Timeout: got %d", cfg.Timeout)
	}
	if cfg.MaxPayload != 30 {
		t.Errorf("MaxPayload: got %d", cfg.MaxPayload)
	}
	if cfg.Callback != "http://callback.example.com" {
		t.Errorf("Callback: got %q", cfg.Callback)
	}
	if !cfg.Verbose {
		t.Error("Verbose: expected true")
	}
	if cfg.LoginURL != "http://from-file.com/login" {
		t.Errorf("LoginURL: got %q", cfg.LoginURL)
	}
	if cfg.Username != "fileuser" {
		t.Errorf("Username: got %q", cfg.Username)
	}
	if cfg.Password != "filepass" {
		t.Errorf("Password: got %q", cfg.Password)
	}
	if !cfg.TestHPP {
		t.Error("TestHPP: expected true")
	}
	if !cfg.WAFBypass {
		t.Error("WAFBypass: expected true")
	}
	if cfg.ConfidenceMin != 0.85 {
		t.Errorf("ConfidenceMin: got %f", cfg.ConfidenceMin)
	}
	if !cfg.AllowPrivate {
		t.Error("AllowPrivate: expected true")
	}
	if cfg.Proxy != "http://proxy.example.com:8080" {
		t.Errorf("Proxy: got %q", cfg.Proxy)
	}
	if cfg.ProxyUsername != "proxyuser" {
		t.Errorf("ProxyUsername: got %q", cfg.ProxyUsername)
	}
	if cfg.ProxyPassword != "proxypass" {
		t.Errorf("ProxyPassword: got %q", cfg.ProxyPassword)
	}
	if !cfg.ProxyInsecure {
		t.Error("ProxyInsecure: expected true")
	}
	if !cfg.Crawl {
		t.Error("Crawl: expected true")
	}
	if cfg.CrawlDepth != 5 {
		t.Errorf("CrawlDepth: got %d", cfg.CrawlDepth)
	}
	if cfg.CrawlMaxPages != 100 {
		t.Errorf("CrawlMaxPages: got %d", cfg.CrawlMaxPages)
	}
	if cfg.TargetsFile != "/tmp/targets.txt" {
		t.Errorf("TargetsFile: got %q", cfg.TargetsFile)
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
	if cfg.PayloadWordlist != "/tmp/wordlist.txt" {
		t.Errorf("PayloadWordlist: got %q", cfg.PayloadWordlist)
	}
	if !cfg.Headless {
		t.Error("Headless: expected true")
	}
	if cfg.JWT != "file.jwt.token" {
		t.Errorf("JWT: got %q", cfg.JWT)
	}
}

// TestApplyTo_CLIOverridesFile verifies that explicitly set CLI flags take
// precedence over file config values, field by field.
func TestApplyTo_CLIOverridesFile(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		fileVal  func(*FileConfig)
		scanVal  func(*ScanConfig)
		check    func(*testing.T, *ScanConfig)
	}{
		{
			name:    "url",
			flag:    "url",
			fileVal: func(fc *FileConfig) { fc.URL = "http://file.com" },
			scanVal: func(sc *ScanConfig) { sc.URL = "http://cli.com" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.URL != "http://cli.com" { t.Errorf("URL: got %q", sc.URL) } },
		},
		{
			name:    "method",
			flag:    "method",
			fileVal: func(fc *FileConfig) { fc.Method = "POST" },
			scanVal: func(sc *ScanConfig) { sc.Method = "PUT" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Method != "PUT" { t.Errorf("Method: got %q", sc.Method) } },
		},
		{
			name:    "header",
			flag:    "header",
			fileVal: func(fc *FileConfig) { fc.Headers = []string{"X-File: 1"} },
			scanVal: func(sc *ScanConfig) { sc.Headers = []string{"X-Cli: 2"} },
			check: func(t *testing.T, sc *ScanConfig) {
				if len(sc.Headers) != 1 || sc.Headers[0] != "X-Cli: 2" {
					t.Errorf("Headers: got %v", sc.Headers)
				}
			},
		},
		{
			name:    "data",
			flag:    "data",
			fileVal: func(fc *FileConfig) { fc.Body = "file-body" },
			scanVal: func(sc *ScanConfig) { sc.Body = "cli-body" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Body != "cli-body" { t.Errorf("Body: got %q", sc.Body) } },
		},
		{
			name:    "cookie",
			flag:    "cookie",
			fileVal: func(fc *FileConfig) { fc.Cookies = []string{"file=c1"} },
			scanVal: func(sc *ScanConfig) { sc.Cookies = []string{"cli=c2"} },
			check: func(t *testing.T, sc *ScanConfig) {
				if len(sc.Cookies) != 1 || sc.Cookies[0] != "cli=c2" {
					t.Errorf("Cookies: got %v", sc.Cookies)
				}
			},
		},
		{
			name:    "output",
			flag:    "output",
			fileVal: func(fc *FileConfig) { fc.Output = "file-out.json" },
			scanVal: func(sc *ScanConfig) { sc.Output = "cli-out.json" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Output != "cli-out.json" { t.Errorf("Output: got %q", sc.Output) } },
		},
		{
			name:    "format",
			flag:    "format",
			fileVal: func(fc *FileConfig) { fc.Format = "html" },
			scanVal: func(sc *ScanConfig) { sc.Format = "json" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Format != "json" { t.Errorf("Format: got %q", sc.Format) } },
		},
		{
			name:    "workers",
			flag:    "workers",
			fileVal: func(fc *FileConfig) { fc.Workers = 50 },
			scanVal: func(sc *ScanConfig) { sc.Workers = 10 },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Workers != 10 { t.Errorf("Workers: got %d", sc.Workers) } },
		},
		{
			name:    "rate-limit",
			flag:    "rate-limit",
			fileVal: func(fc *FileConfig) { fc.RateLimit = 200 },
			scanVal: func(sc *ScanConfig) { sc.RateLimit = 50 },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.RateLimit != 50 { t.Errorf("RateLimit: got %d", sc.RateLimit) } },
		},
		{
			name:    "timeout",
			flag:    "timeout",
			fileVal: func(fc *FileConfig) { fc.Timeout = 60 },
			scanVal: func(sc *ScanConfig) { sc.Timeout = 30 },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Timeout != 30 { t.Errorf("Timeout: got %d", sc.Timeout) } },
		},
		{
			name:    "max-payloads",
			flag:    "max-payloads",
			fileVal: func(fc *FileConfig) { fc.MaxPayload = 100 },
			scanVal: func(sc *ScanConfig) { sc.MaxPayload = 50 },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.MaxPayload != 50 { t.Errorf("MaxPayload: got %d", sc.MaxPayload) } },
		},
		{
			name:    "waf-bypass",
			flag:    "waf-bypass",
			fileVal: func(fc *FileConfig) { fc.WAFBypass = true },
			scanVal: func(sc *ScanConfig) { sc.WAFBypass = false },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.WAFBypass { t.Error("WAFBypass: expected false (CLI override)") } },
		},
		{
			name:    "confidence",
			flag:    "confidence",
			fileVal: func(fc *FileConfig) { fc.ConfidenceMin = 0.90 },
			scanVal: func(sc *ScanConfig) { sc.ConfidenceMin = 0.60 },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.ConfidenceMin != 0.60 { t.Errorf("ConfidenceMin: got %f", sc.ConfidenceMin) } },
		},
		{
			name:    "allow-private",
			flag:    "allow-private",
			fileVal: func(fc *FileConfig) { fc.AllowPrivate = true },
			scanVal: func(sc *ScanConfig) { sc.AllowPrivate = false },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.AllowPrivate { t.Error("AllowPrivate: expected false") } },
		},
		{
			name:    "crawl",
			flag:    "crawl",
			fileVal: func(fc *FileConfig) { fc.Crawl = true },
			scanVal: func(sc *ScanConfig) { sc.Crawl = false },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Crawl { t.Error("Crawl: expected false") } },
		},
		{
			name:    "random-ua",
			flag:    "random-ua",
			fileVal: func(fc *FileConfig) { fc.RandomUA = true },
			scanVal: func(sc *ScanConfig) { sc.RandomUA = false },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.RandomUA { t.Error("RandomUA: expected false") } },
		},
		{
			name:    "payload-preset",
			flag:    "payload-preset",
			fileVal: func(fc *FileConfig) { fc.PayloadPreset = "full" },
			scanVal: func(sc *ScanConfig) { sc.PayloadPreset = "minimal" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.PayloadPreset != "minimal" { t.Errorf("PayloadPreset: got %q", sc.PayloadPreset) } },
		},
		{
			name:    "headless",
			flag:    "headless",
			fileVal: func(fc *FileConfig) { fc.Headless = true },
			scanVal: func(sc *ScanConfig) { sc.Headless = false },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.Headless { t.Error("Headless: expected false") } },
		},
		{
			name:    "jwt",
			flag:    "jwt",
			fileVal: func(fc *FileConfig) { fc.JWT = "file.jwt" },
			scanVal: func(sc *ScanConfig) { sc.JWT = "cli.jwt" },
			check:   func(t *testing.T, sc *ScanConfig) { if sc.JWT != "cli.jwt" { t.Errorf("JWT: got %q", sc.JWT) } },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FileConfig{}
			tt.fileVal(fc)

			sc := &ScanConfig{}
			tt.scanVal(sc)

			flags := map[string]bool{tt.flag: true}
			fc.ApplyTo(sc, flags)
			tt.check(t, sc)
		})
	}
}

// TestApplyTo_ProxyFromFile verifies proxy settings are correctly loaded from file.
func TestApplyTo_ProxyFromFile(t *testing.T) {
	fc := &FileConfig{
		Proxy:         "http://127.0.0.1:8080",
		ProxyUsername: "user",
		ProxyPassword: "pass",
		ProxyInsecure: true,
	}
	cfg := &ScanConfig{}
	fc.ApplyTo(cfg, map[string]bool{})

	if cfg.Proxy != "http://127.0.0.1:8080" {
		t.Errorf("Proxy: got %q", cfg.Proxy)
	}
	if cfg.ProxyUsername != "user" {
		t.Errorf("ProxyUsername: got %q", cfg.ProxyUsername)
	}
	if cfg.ProxyPassword != "pass" {
		t.Errorf("ProxyPassword: got %q", cfg.ProxyPassword)
	}
	if !cfg.ProxyInsecure {
		t.Error("ProxyInsecure: expected true")
	}
}

// TestApplyTo_ProxyCLIOverride verifies CLI proxy flags override file values.
func TestApplyTo_ProxyCLIOverride(t *testing.T) {
	fc := &FileConfig{
		Proxy:         "http://file-proxy:8080",
		ProxyUsername: "fileuser",
		ProxyPassword: "filepass",
		ProxyInsecure: true,
	}
	cfg := &ScanConfig{
		Proxy:         "http://cli-proxy:9090",
		ProxyUsername: "cliuser",
		ProxyPassword: "clipass",
		ProxyInsecure: false,
	}
	flags := map[string]bool{
		"proxy":           true,
		"proxy-username":  true,
		"proxy-password":  true,
		"proxy-insecure":  true,
	}
	fc.ApplyTo(cfg, flags)

	if cfg.Proxy != "http://cli-proxy:9090" {
		t.Errorf("Proxy: got %q", cfg.Proxy)
	}
	if cfg.ProxyUsername != "cliuser" {
		t.Errorf("ProxyUsername: got %q", cfg.ProxyUsername)
	}
	if cfg.ProxyPassword != "clipass" {
		t.Errorf("ProxyPassword: got %q", cfg.ProxyPassword)
	}
	if cfg.ProxyInsecure {
		t.Error("ProxyInsecure: expected false (CLI override)")
	}
}

// TestApplyTo_PayloadPresetFromFile verifies payload preset is loaded from file.
func TestApplyTo_PayloadPresetFromFile(t *testing.T) {
	tests := []struct {
		name   string
		preset string
	}{
		{"minimal", "minimal"},
		{"standard", "standard"},
		{"full", "full"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FileConfig{PayloadPreset: tt.preset}
			cfg := &ScanConfig{}
			fc.ApplyTo(cfg, map[string]bool{})
			if cfg.PayloadPreset != tt.preset {
				t.Errorf("PayloadPreset: got %q, want %q", cfg.PayloadPreset, tt.preset)
			}
		})
	}
}

// TestApplyTo_CrawlSettingsFromFile verifies crawl settings are loaded from file.
func TestApplyTo_CrawlSettingsFromFile(t *testing.T) {
	fc := &FileConfig{
		Crawl:         true,
		CrawlDepth:    7,
		CrawlMaxPages: 200,
	}
	cfg := &ScanConfig{}
	fc.ApplyTo(cfg, map[string]bool{})

	if !cfg.Crawl {
		t.Error("Crawl: expected true")
	}
	if cfg.CrawlDepth != 7 {
		t.Errorf("CrawlDepth: got %d", cfg.CrawlDepth)
	}
	if cfg.CrawlMaxPages != 200 {
		t.Errorf("CrawlMaxPages: got %d", cfg.CrawlMaxPages)
	}
}

// TestApplyTo_CrawlSettingsCLIOverride verifies CLI crawl flags override file values.
func TestApplyTo_CrawlSettingsCLIOverride(t *testing.T) {
	fc := &FileConfig{
		Crawl:         true,
		CrawlDepth:    7,
		CrawlMaxPages: 200,
	}
	cfg := &ScanConfig{
		Crawl:         false,
		CrawlDepth:    3,
		CrawlMaxPages: 50,
	}
	flags := map[string]bool{
		"crawl":           true,
		"crawl-depth":     true,
		"crawl-max-pages": true,
	}
	fc.ApplyTo(cfg, flags)

	if cfg.Crawl {
		t.Error("Crawl: expected false (CLI override)")
	}
	if cfg.CrawlDepth != 3 {
		t.Errorf("CrawlDepth: got %d, want 3", cfg.CrawlDepth)
	}
	if cfg.CrawlMaxPages != 50 {
		t.Errorf("CrawlMaxPages: got %d, want 50", cfg.CrawlMaxPages)
	}
}

// TestApplyTo_LoadFromYAMLThenApply verifies the full flow: load YAML from disk,
// then apply with flag precedence.
func TestApplyTo_LoadFromYAMLThenApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.yml")

	content := `
url: "http://config-file.com/search"
workers: 15
rate-limit: 60
timeout: 40
waf-bypass: true
confidence: 0.75
payload-preset: "minimal"
crawl: true
crawl-depth: 4
headers:
  - "X-API-Key: secret123"
jwt: "yaml.jwt.token"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fc, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	cfg := &ScanConfig{
		URL: "http://cli-override.com", // CLI flag set — should win
	}
	flags := map[string]bool{"url": true}
	fc.ApplyTo(cfg, flags)

	// URL: CLI flag wins
	if cfg.URL != "http://cli-override.com" {
		t.Errorf("URL: got %q, want CLI value", cfg.URL)
	}
	// Everything else: loaded from file
	if cfg.Workers != 15 {
		t.Errorf("Workers: got %d", cfg.Workers)
	}
	if cfg.RateLimit != 60 {
		t.Errorf("RateLimit: got %d", cfg.RateLimit)
	}
	if cfg.Timeout != 40 {
		t.Errorf("Timeout: got %d", cfg.Timeout)
	}
	if !cfg.WAFBypass {
		t.Error("WAFBypass: expected true")
	}
	if cfg.ConfidenceMin != 0.75 {
		t.Errorf("ConfidenceMin: got %f", cfg.ConfidenceMin)
	}
	if cfg.PayloadPreset != "minimal" {
		t.Errorf("PayloadPreset: got %q", cfg.PayloadPreset)
	}
	if !cfg.Crawl {
		t.Error("Crawl: expected true")
	}
	if cfg.CrawlDepth != 4 {
		t.Errorf("CrawlDepth: got %d", cfg.CrawlDepth)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0] != "X-API-Key: secret123" {
		t.Errorf("Headers: got %v", cfg.Headers)
	}
	if cfg.JWT != "yaml.jwt.token" {
		t.Errorf("JWT: got %q", cfg.JWT)
	}
}

// TestApplyTo_AllFlagsSet verifies that when ALL CLI flags are set,
// NO file values override anything.
func TestApplyTo_AllFlagsSet(t *testing.T) {
	fc := &FileConfig{
		URL:             "http://file.com",
		Method:          "POST",
		Headers:         []string{"X-File: 1"},
		Body:            "file-body",
		Cookies:         []string{"file=c1"},
		Output:          "file.json",
		Format:          "html",
		Workers:         99,
		RateLimit:       99,
		Timeout:         99,
		MaxPayload:      99,
		Callback:        "http://file.callback",
		Verbose:         true,
		LoginURL:        "http://file.com/login",
		Username:        "fileuser",
		Password:        "filepass",
		TestHPP:         true,
		WAFBypass:       true,
		ConfidenceMin:   0.99,
		AllowPrivate:    true,
		Proxy:           "http://file.proxy",
		ProxyUsername:   "fileproxyuser",
		ProxyPassword:   "fileproxypass",
		ProxyInsecure:   true,
		Crawl:           true,
		CrawlDepth:      9,
		CrawlMaxPages:   999,
		TargetsFile:     "/file/targets",
		RandomUA:        true,
		AdaptiveRate:    true,
		PayloadPreset:   "full",
		PayloadWordlist: "/file/wordlist",
		Headless:        true,
		JWT:             "file.jwt",
	}

	cfg := &ScanConfig{
		URL:             "http://cli.com",
		Method:          "DELETE",
		Headers:         []string{"X-Cli: 2"},
		Body:            "cli-body",
		Cookies:         []string{"cli=c2"},
		Output:          "cli.json",
		Format:          "json",
		Workers:         5,
		RateLimit:       10,
		Timeout:         15,
		MaxPayload:      20,
		Callback:        "http://cli.callback",
		Verbose:         false,
		LoginURL:        "http://cli.com/login",
		Username:        "cliuser",
		Password:        "clipass",
		TestHPP:         false,
		WAFBypass:       false,
		ConfidenceMin:   0.50,
		AllowPrivate:    false,
		Proxy:           "http://cli.proxy",
		ProxyUsername:   "cliproxyuser",
		ProxyPassword:   "cliproxypass",
		ProxyInsecure:   false,
		Crawl:           false,
		CrawlDepth:      2,
		CrawlMaxPages:   50,
		TargetsFile:     "/cli/targets",
		RandomUA:        false,
		AdaptiveRate:    false,
		PayloadPreset:   "minimal",
		PayloadWordlist: "/cli/wordlist",
		Headless:        false,
		JWT:             "cli.jwt",
	}

	// All flags explicitly set
	flags := map[string]bool{
		"url":               true,
		"method":            true,
		"header":            true,
		"data":              true,
		"cookie":            true,
		"output":            true,
		"format":            true,
		"workers":           true,
		"rate-limit":        true,
		"timeout":           true,
		"max-payloads":      true,
		"callback":          true,
		"verbose":           true,
		"login-url":         true,
		"username":          true,
		"password":          true,
		"hpp":               true,
		"waf-bypass":        true,
		"confidence":        true,
		"allow-private":     true,
		"proxy":             true,
		"proxy-username":    true,
		"proxy-password":    true,
		"proxy-insecure":    true,
		"crawl":             true,
		"crawl-depth":       true,
		"crawl-max-pages":   true,
		"targets-file":      true,
		"random-ua":         true,
		"adaptive-rate":     true,
		"payload-preset":    true,
		"payload-wordlist":  true,
		"headless":          true,
		"jwt":               true,
	}

	fc.ApplyTo(cfg, flags)

	// Every field should retain its CLI value
	if cfg.URL != "http://cli.com" {
		t.Errorf("URL: got %q", cfg.URL)
	}
	if cfg.Method != "DELETE" {
		t.Errorf("Method: got %q", cfg.Method)
	}
	if cfg.Workers != 5 {
		t.Errorf("Workers: got %d", cfg.Workers)
	}
	if cfg.PayloadPreset != "minimal" {
		t.Errorf("PayloadPreset: got %q", cfg.PayloadPreset)
	}
	if cfg.JWT != "cli.jwt" {
		t.Errorf("JWT: got %q", cfg.JWT)
	}
	if cfg.Crawl {
		t.Error("Crawl: expected false")
	}
	if cfg.Proxy != "http://cli.proxy" {
		t.Errorf("Proxy: got %q", cfg.Proxy)
	}
}

// TestApplyTo_EmptyFileConfig verifies that an empty FileConfig doesn't
// overwrite any ScanConfig values (all checks use non-zero guards).
func TestApplyTo_EmptyFileConfig(t *testing.T) {
	fc := &FileConfig{} // all zero values
	cfg := &ScanConfig{
		URL:           "http://existing.com",
		Method:        "POST",
		Workers:       10,
		RateLimit:     50,
		Timeout:       30,
		MaxPayload:    50,
		Verbose:       true,
		WAFBypass:     true,
		ConfidenceMin: 0.70,
		AllowPrivate:  true,
		Crawl:         true,
		CrawlDepth:    3,
		RandomUA:      true,
		AdaptiveRate:  true,
		PayloadPreset: "full",
		Headless:      true,
		JWT:           "existing.jwt",
	}
	fc.ApplyTo(cfg, map[string]bool{})

	// Nothing should change
	if cfg.URL != "http://existing.com" {
		t.Errorf("URL: got %q", cfg.URL)
	}
	if cfg.Method != "POST" {
		t.Errorf("Method: got %q", cfg.Method)
	}
	if cfg.Workers != 10 {
		t.Errorf("Workers: got %d", cfg.Workers)
	}
	if cfg.PayloadPreset != "full" {
		t.Errorf("PayloadPreset: got %q", cfg.PayloadPreset)
	}
}
