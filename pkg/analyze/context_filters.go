package analyze

import (
	ctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"strings"
)

type ContextFilters map[ctx.ContextType]*FilterProfile

// DetectContextFilters separates each reflection before detecting its context.
// Only delimiter-bounded injected bytes can influence the profile; surrounding
// tag quotes or another parameter's transformations cannot contaminate it.
// A context is blocked only if every known occurrence in that context blocks it.
func DetectContextFilters(body, startMarker, endMarker string) ContextFilters {
	profiles := make(ContextFilters)
	if startMarker == "" || endMarker == "" {
		return profiles
	}
	// Whole-document classification is bounded. Beyond this budget ambiguity
	// keeps all payloads, rather than multiplying attacker-controlled parse work.
	if len(body) > 256*1024 || strings.Count(body, startMarker) > 16 {
		return nil
	}
	d := ctx.NewDetector()
	for from := 0; from < len(body); {
		i := strings.Index(body[from:], startMarker)
		if i < 0 {
			break
		}
		i += from
		from = i + len(startMarker)
		tail := body[from:min(len(body), from+256)]
		end := strings.Index(tail, endMarker)
		if end < 0 {
			return nil
		} // truncated/ambiguous probes never justify pruning
		fragment := tail[:end]
		marked := strings.ReplaceAll(body[:i], startMarker, strings.Repeat("z", len(startMarker))) + startMarker + strings.ReplaceAll(body[from:], startMarker, strings.Repeat("z", len(startMarker)))
		contexts, _ := d.Detect(ctx.Reflection{Content: marked, ParamValue: startMarker, Offset: i})
		if len(contexts) != 1 || contexts[0].ParseError != "" || !contexts[0].IsExploitable() {
			return nil
		}
		kind := contexts[0].Type
		p := &FilterProfile{StripsAngleBrackets: !strings.ContainsAny(fragment, "<>") && !strings.Contains(fragment, "&lt;") && !strings.Contains(fragment, "&gt;"), EncodesAngleBrackets: !strings.ContainsAny(fragment, "<>") && (strings.Contains(fragment, "&lt;") || strings.Contains(fragment, "&gt;")), EncodesDoubleQuote: !strings.Contains(fragment, `"`), EncodesSingleQuote: !strings.Contains(fragment, `'`)}
		if prior := profiles[kind]; prior != nil {
			// Merge angle blockage by capability, even if one occurrence strips
			// and another encodes. A single raw occurrence keeps the capability.
			blocked := !prior.AllowsAngleBrackets() && !p.AllowsAngleBrackets()
			prior.StripsAngleBrackets, prior.EncodesAngleBrackets = blocked, false
			prior.EncodesDoubleQuote = prior.EncodesDoubleQuote && p.EncodesDoubleQuote
			prior.EncodesSingleQuote = prior.EncodesSingleQuote && p.EncodesSingleQuote
		} else {
			profiles[kind] = p
		}
	}
	return profiles
}
