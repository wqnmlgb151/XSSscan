package dom

import (
	"slices"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

// All findings come from one target's source matrix. Preserve source and sink
// identity while collapsing repeated payload variants (including path probes).
func aggregateDOMFindings(findings []model.Finding) []model.Finding {
	type key struct{ source, sink string }
	positions := make(map[key]int)
	var out []model.Finding
	for _, finding := range findings {
		k := key{finding.Parameter, finding.Evidence.Context}
		if i, exists := positions[k]; exists {
			if !slices.Contains(out[i].Payloads, finding.Payload) {
				out[i].Payloads = append(out[i].Payloads, finding.Payload)
			}
		} else {
			positions[k] = len(out)
			finding.Payloads = []string{finding.Payload}
			out = append(out, finding)
		}
	}
	return out
}
