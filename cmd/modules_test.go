package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestDefaultTypesAndLegacyExclusion(t *testing.T) {
	defer saveCfg()()
	cfg = ScanConfig{}
	if err := configureTypes(nil); err != nil {
		t.Fatal(err)
	}
	if cfg.Types != "reflected,dom,stored,blind" || !cfg.Headless || !cfg.EnableStored {
		t.Fatalf("default lost types: %+v", cfg)
	}
	cfg = ScanConfig{Types: "all"}
	cmd := &cobra.Command{}
	cmd.Flags().Bool("headless", true, "")
	if err := cmd.Flags().Set("headless", "false"); err != nil {
		t.Fatal(err)
	}
	if err := configureTypes(cmd); err != nil {
		t.Fatal(err)
	}
	if selectedType("dom") {
		t.Fatal("legacy explicit false ignored")
	}
	cfg = ScanConfig{Types: "reflected,stored", ExcludeTypes: "stored"}
	if err := configureTypes(nil); err != nil {
		t.Fatal(err)
	}
	if cfg.Types != "reflected" || cfg.Headless || cfg.EnableStored {
		t.Fatal("explicit selection ignored")
	}
}
