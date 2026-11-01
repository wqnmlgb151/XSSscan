package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurationPresenceAndStrictKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	for _, bad := range []string{"unknown-option: true\n", "workers: 1\nworkers: 2\n", "types: reflected\n---\nworkers: 2\n"} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted bad config %q", bad)
		}
	}
	if err := os.WriteFile(path, []byte("verify-execution: false\nheadless: false\nstored: false\nmodule-timeout: 0\nrequest-budget: 0\nmax-payloads: 0\nheaders: []\nbody: ''\nprobe: false\noauth-scope: ''\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fc, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	config := ScanConfig{VerifyExecution: true, Headless: true, EnableStored: true, ModuleTimeout: 300, RequestBudget: 10000, MaxPayload: 50, Headers: []string{"Authorization: token"}, Body: "old", EnableProbe: true, OAuthScope: "openid"}
	fc.ApplyTo(&config, nil)
	if config.VerifyExecution || config.Headless || config.EnableStored || config.ModuleTimeout != 0 || config.RequestBudget != 0 || config.MaxPayload != 0 || len(config.Headers) != 0 || config.Body != "" || config.EnableProbe || config.OAuthScope != "" {
		t.Fatalf("zero values ignored: %+v", config)
	}
	config.VerifyExecution = true
	config.ModuleTimeout = 10
	fc.ApplyTo(&config, map[string]bool{"verify-execution": true, "module-timeout": true})
	if !config.VerifyExecution || config.ModuleTimeout != 10 {
		t.Fatal("CLI precedence lost")
	}
}
