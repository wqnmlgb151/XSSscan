package main

import "testing"

func TestFullVerificationWindowConfigPrecedence(t *testing.T) {
	flag := rootCmd.Flags().Lookup("verify-full-window")
	if flag == nil || flag.DefValue != "false" {
		t.Fatal("compatibility opt-in default changed")
	}
	var config ScanConfig
	file := FileConfig{VerifyFullWindow: true}
	file.ApplyTo(&config, nil)
	if !config.VerifyFullWindow {
		t.Fatal("YAML full window ignored")
	}
	config.VerifyFullWindow = false
	file.ApplyTo(&config, map[string]bool{"verify-full-window": true})
	if config.VerifyFullWindow {
		t.Fatal("explicit CLI false overridden")
	}
}
