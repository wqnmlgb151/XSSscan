package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

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
	config := ScanConfig{URL: "http://127.0.0.1/", IncludeRawEvidence: true}
	if err := validateConfig(&config); err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("raw evidence accepted without private output: %v", err)
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
}
