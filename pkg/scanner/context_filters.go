package scanner

import (
	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/payload"
)

func pruneContextPayloads(input []payload.Payload, profiles analyze.ContextFilters) []payload.Payload {
	if len(profiles) == 0 {
		return input
	}
	out := make([]payload.Payload, 0, len(input))
	// Evaluate classes together so the conservative all-pruned fallback remains
	// per context, rather than reverting or dropping an unrelated context.
	groups := make(map[int][]payload.Payload)
	for _, p := range input {
		groups[int(p.Context)] = append(groups[int(p.Context)], p)
	}
	kept := make(map[string]bool)
	for _, group := range groups {
		for _, p := range prunePayloads(group, profiles[group[0].Context]) {
			kept[p.Value] = true
		}
	}
	for _, p := range input {
		if kept[p.Value] {
			out = append(out, p)
		}
	}
	return out
}
