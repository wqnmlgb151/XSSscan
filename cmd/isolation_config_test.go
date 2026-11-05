package main

import "testing"

func TestSiteIsolationCompatibilityConfig(t *testing.T) {
	flag := rootCmd.Flags().Lookup("chrome-disable-site-isolation")
	if flag == nil || flag.DefValue != "false" {
		t.Fatal("site isolation opt-out must default false")
	}
	file := FileConfig{ChromeDisableSiteIsolation: true, ChromeLegacyStartup: true}
	var config ScanConfig
	file.ApplyTo(&config, nil)
	if !config.ChromeDisableSiteIsolation || !config.ChromeLegacyStartup {
		t.Fatal("YAML compatibility switch ignored")
	}
	config.ChromeDisableSiteIsolation = false
	file.ApplyTo(&config, map[string]bool{"chrome-disable-site-isolation": true})
	if config.ChromeDisableSiteIsolation {
		t.Fatal("explicit CLI false overridden")
	}
}
