package dom

import (
	_ "embed"
	"strings"
)

// Retain the obsolete fallback only for local historical regression tests.
//
//go:embed sinks.js
var sinkDetectionScript string

func buildSinkScript(marker string) string {
	return strings.Replace(sinkDetectionScript, "{{MARKER}}", marker, 1)
}
