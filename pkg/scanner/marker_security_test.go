package scanner

import (
	"strings"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
)

func TestCustomMarkerProbeDimensionsMatchDefaults(t *testing.T) {
	for kind, defaults := range probeLibrary {
		probes := GetProbesForContext(kind, "auditmarker")
		if len(probes) != len(defaults) {
			t.Fatalf("probe dimensions changed: %v", kind)
		}
		for i, probe := range probes {
			if probe.Probe != strings.ReplaceAll(defaults[i].Probe, analyze.MarkerPrefix, "auditmarker") {
				t.Fatal("custom probe string mismatch")
			}
			for _, body := range []string{defaults[i].Probe, `<div x="` + defaults[i].Probe + `"></div>`, "inert"} {
				if probe.Validator(strings.ReplaceAll(body, analyze.MarkerPrefix, "auditmarker")) != defaults[i].Validator(body) {
					t.Fatalf("validator semantics changed: %v/%d", kind, i)
				}
			}
		}
	}
}
