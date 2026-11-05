package scanner

import (
	"sort"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	ctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
)

// pruneContextPayloads narrows the candidate set using the per-context filter
// profiles. It returns the pruned set plus the contexts the profile emptied, so the
// caller can report that a reflection position has no candidate left rather than
// letting a silently empty budget read as "nothing to find".
func pruneContextPayloads(input []payload.Payload, profiles analyze.ContextFilters) ([]payload.Payload, []ctx.ContextType) {
	if len(profiles) == 0 {
		return input, nil
	}
	// Evaluate classes together so the conservative all-pruned fallback remains
	// per context, rather than reverting or dropping an unrelated context.
	groups := make(map[ctx.ContextType][]payload.Payload)
	for _, p := range input {
		groups[p.Context] = append(groups[p.Context], p)
	}
	kept := make(map[string]bool)
	var emptied []ctx.ContextType
	for contextType, group := range groups {
		survivors := prunePayloads(group, profiles[contextType])
		if len(survivors) == 0 {
			emptied = append(emptied, contextType)
		}
		for _, p := range survivors {
			kept[p.Value] = true
		}
	}
	out := make([]payload.Payload, 0, len(input))
	for _, p := range input {
		if kept[p.Value] {
			out = append(out, p)
		}
	}
	sort.Slice(emptied, func(i, j int) bool { return emptied[i] < emptied[j] })
	return out, emptied
}

/*
Context-budget safety net (ENGINEERING_PLAN.md §25.6, §25.13).

Using the filter profile to narrow candidates before anything is sent is the
highest-leverage request reduction available: on a server that encodes angle
brackets, tag payloads cannot execute as sent, and the profile has already measured
that. Two rules keep the narrowing from becoming a coverage loss:

  - A profile must never empty a context silently. When it does, the run widens once
    so a wrong profile cannot cost a finding, and records that it happened.
  - Widening still respects the profile. It admits candidates written for other
    contexts, but not candidates that themselves depend on the blocked capability —
    otherwise the safety net would restore exactly what the profile measured and the
    reduction would be back to zero.
*/

// widenForEmptiedContexts builds the cross-context safety net used when a filter
// profile removed every candidate for one of an injection point's contexts.
//
// The candidates are regenerated rather than recovered from the pruned slice, so the
// widening set does not depend on the pruning order. Each is then judged by the
// profile that governs where it would execute.
func widenForEmptiedContexts(candidates []payload.Payload, profiles analyze.ContextFilters) []payload.Payload {
	if len(candidates) == 0 || len(profiles) == 0 {
		return nil
	}
	if len(profiles) == 1 {
		// One profile governs the whole injection point, so every candidate is judged
		// against it regardless of the context it was written for.
		for _, profile := range profiles {
			return filterByProfile(candidates, profile)
		}
	}
	out := make([]payload.Payload, 0, len(candidates))
	for _, p := range candidates {
		if profile := profiles[p.Context]; profile != nil && payloadBlockedByProfile(p.Value, profile) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// filterByProfile keeps the payloads a single profile does not rule out.
func filterByProfile(payloads []payload.Payload, profile *analyze.FilterProfile) []payload.Payload {
	out := make([]payload.Payload, 0, len(payloads))
	for _, p := range payloads {
		if payloadBlockedByProfile(p.Value, profile) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// payloadBlockedByProfile reports whether a payload depends on a capability the
// profile says the server removes or rewrites.
//
// It is deliberately literal: it asks whether the payload needs the metacharacter,
// not whether the metacharacter appears somewhere in the string. A payload that merely
// contains an angle bracket in an inert position is still treated as dependent, which
// errs toward pruning; the widening safety net is what makes that acceptable.
func payloadBlockedByProfile(value string, profile *analyze.FilterProfile) bool {
	if profile == nil {
		return false
	}
	if strings.ContainsAny(value, "<>") && !profile.AllowsAngleBrackets() {
		return true
	}
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, `"`) && !profile.AllowsDoubleQuote() {
		return true
	}
	if strings.HasPrefix(trimmed, `'`) && !profile.AllowsSingleQuote() {
		return true
	}
	return false
}

// contextNames renders context types for diagnostics.
func contextNames(types []ctx.ContextType) []string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, t.String())
	}
	return names
}
