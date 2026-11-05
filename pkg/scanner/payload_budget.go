package scanner

import (
	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
)

// limitPayloads shares a binding budget across contexts and quote breakouts.
// Keep generator order within each group. Unlimited/nonbinding budgets retain
// the original slice and order; selection never changes candidate metadata.
func limitPayloads(input []payload.Payload, limit int) []payload.Payload {
	if limit <= 0 || len(input) <= limit {
		return input
	}
	type groupKey struct {
		context xctx.ContextType
		quote   byte
	}
	indices := make(map[groupKey]int)
	var groups [][]int
	for i, p := range input {
		key := groupKey{context: p.Context}
		if (p.Context == xctx.ContextJSString || p.Context == xctx.ContextHTMLAttrValue) && len(p.Value) > 0 {
			if p.Value[0] == '\'' || p.Value[0] == '"' {
				key.quote = p.Value[0]
			}
		}
		index, ok := indices[key]
		if !ok {
			index = len(groups)
			indices[key] = index
			groups = append(groups, nil)
		}
		groups[index] = append(groups[index], i)
	}
	selected := make([]payload.Payload, 0, limit)
	for round := 0; len(selected) < limit; round++ {
		for _, group := range groups {
			if round < len(group) {
				selected = append(selected, input[group[round]])
				if len(selected) == limit {
					return selected
				}
			}
		}
	}
	return selected
}
