package main

import (
	"os"
	"strings"

	"github.com/fatih/color"
)

// Status messages follow the merged CLI/YAML configuration and stay separate
// from stdout results. Errors still return to Cobra and reports retain diagnostics.
func statusOutput(shade color.Attribute, format string, args ...any) {
	if cfg.Silent {
		return
	}
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	color.New(shade).Fprintf(os.Stderr, format, args...)
}

func statusCyan(format string, args ...any)   { statusOutput(color.FgCyan, format, args...) }
func statusYellow(format string, args ...any) { statusOutput(color.FgYellow, format, args...) }
func statusGreen(format string, args ...any)  { statusOutput(color.FgGreen, format, args...) }
