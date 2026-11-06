package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestCLIDefaultReportPreservesReplayEvidence(t *testing.T) {
	defer saveCfg()()
	flag := rootCmd.Flags().Lookup("include-raw-evidence")
	raw, err := strconv.ParseBool(flag.DefValue)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "html", "markdown", "sarif", "junit"} {
		output := filepath.Join(t.TempDir(), "report")
		cfg = ScanConfig{Silent: true, Output: output, Format: format, IncludeRawEvidence: raw}
		finding := model.Finding{Type: model.ReflectedXSS, URL: "http://127.0.0.1/?token=query-canary", Parameter: "q", ParamType: model.ParamBody,
			RawRequest:  "POST /?token=query-canary HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer auth-canary\r\nCookie: session=cookie-canary\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncsrf_token=body-canary",
			RawResponse: "HTTP/1.1 200 OK\r\nSet-Cookie: session=response-canary\r\n\r\noriginal response"}
		if err := reportScanResults([]model.Finding{finding}, model.ScanStats{Status: model.ScanCompleted}, []string{finding.URL}, time.Now()); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"query-canary", "auth-canary", "cookie-canary", "body-canary", "response-canary", "original response"} {
			if !strings.Contains(string(data), value) {
				t.Fatalf("%s default report lost %q", format, value)
			}
		}
	}
}

// Retain the historical test identity while checking both explicit modes.
func TestCLIReportsSafeByDefaultAndRawIsExplicit(t *testing.T) {
	defer saveCfg()()
	for _, format := range []string{"json", "html", "markdown", "sarif", "junit"} {
		for _, raw := range []bool{false, true} {
			output := filepath.Join(t.TempDir(), "report")
			cfg = ScanConfig{Silent: true, Output: output, Format: format, IncludeRawEvidence: raw}
			finding := model.Finding{Type: model.ReflectedXSS, Severity: model.High, URL: "http://local.test/?q=x", Parameter: "q", ParamType: model.ParamQuery, Payload: "<img onerror=alert(1)>", RawRequest: "GET /?q=x HTTP/1.1\r\nHost: local.test\r\nAuthorization: Bearer cli-canary-1234\r\n\r\n", RawResponse: "HTTP/1.1 200 OK\r\nSet-Cookie: session=cli-cookie-4567\r\n\r\n"}
			if err := reportScanResults([]model.Finding{finding}, model.ScanStats{Status: model.ScanCompleted}, []string{finding.URL}, time.Now()); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"cli-canary-1234", "cli-cookie-4567"} {
				if strings.Contains(string(data), secret) != raw {
					t.Fatalf("format=%s raw=%t credential policy violated", format, raw)
				}
			}
		}
	}
}

func TestRawEvidenceRequiresReportOutput(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{URL: "http://127.0.0.1/", IncludeRawEvidence: true}
	if err := validateConfig(&cfg); err != nil {
		t.Fatalf("summary-only scan with default settings was rejected: %v", err)
	}
	stdout, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	previous := os.Stdout
	os.Stdout = stdout
	defer func() { os.Stdout = previous }()
	findings := []model.Finding{{URL: cfg.URL, RawRequest: "Authorization: Bearer summary-canary"}}
	if err := reportScanResults(findings, model.ScanStats{Status: model.ScanCompleted}, []string{cfg.URL}, time.Now()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Findings:  1") || strings.Contains(string(body), "summary-canary") {
		t.Fatal("console should show the scan summary without raw HTTP evidence")
	}
}

func TestRawEvidenceYAMLIsExplicitAndCLIOverrideWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("include-raw-evidence: true\noutput: private.json\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	var config ScanConfig
	file.ApplyTo(&config, nil)
	if !config.IncludeRawEvidence {
		t.Fatal("explicit YAML raw option ignored")
	}
	config.IncludeRawEvidence = false
	file.ApplyTo(&config, map[string]bool{"include-raw-evidence": true})
	if config.IncludeRawEvidence {
		t.Fatal("YAML overrode explicit CLI false")
	}
	if err := os.WriteFile(path, []byte("include-raw-evidence: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err = LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	config.IncludeRawEvidence = true
	file.ApplyTo(&config, nil)
	if config.IncludeRawEvidence {
		t.Fatal("explicit YAML false did not override the raw default")
	}
	config.IncludeRawEvidence = true
	file.ApplyTo(&config, map[string]bool{"include-raw-evidence": true})
	if !config.IncludeRawEvidence {
		t.Fatal("YAML overrode explicit CLI true")
	}
}
