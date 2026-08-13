package analyze

import (
	"strings"
)

// FilterProfile describes how the server transforms injected special
// characters — the XSStrike "filter discovery" idea. By sending one probe
// containing all metacharacters and comparing the reflection, the scanner
// knows which payload classes can survive and which bypass mutations to
// prefer, instead of blindly sending everything.
type FilterProfile struct {
	StripsAngleBrackets  bool            // < > removed entirely
	EncodesAngleBrackets bool            // < > → &lt; &gt;
	EncodesQuotes        bool            // " → &quot; or ' → &#39;
	FiltersEventHandlers bool            // on\w+= removed or mangled
	FiltersKeywords      map[string]bool // alert(, javascript: etc. removed
	LengthLimit          int             // 0 = no truncation observed
}

// FilterProbeValue contains one occurrence of every metacharacter whose
// fate the profile needs to determine.
const FilterProbeValue = "xsscan<>\"'()=onerror=alert(javascript:"

// DetectFilterProfile analyzes a response body containing the reflection of
// filterProbeValue. Returns nil if the probe value cannot be located.
func DetectFilterProfile(body string) *FilterProfile {
	if !strings.Contains(body, "xsscan") {
		return nil
	}

	p := &FilterProfile{FiltersKeywords: make(map[string]bool)}

	// Angle brackets: stripped vs entity-encoded vs preserved.
	switch {
	case strings.Contains(body, "&lt;") && strings.Contains(body, "&gt;") &&
		!strings.Contains(body, "xsscan<"):
		p.EncodesAngleBrackets = true
	case !strings.Contains(body, "<") && !strings.Contains(body, ">"):
		p.StripsAngleBrackets = true
	}

	// Quotes: encoded vs preserved.
	if strings.Contains(body, "&quot;") || strings.Contains(body, "&#39;") {
		p.EncodesQuotes = true
	}

	// Event handlers: onerror= mangled or missing while xsscan survives.
	if !strings.Contains(body, "onerror") && !strings.Contains(body, "o_nerror") {
		// Can't distinguish "filtered" from "truncated before onerror" without
		// more context — treat missing as filtered only when the probe tail
		// (alert() which comes AFTER onerror=) also survives.
		if !strings.Contains(body, "alert(") {
			p.FiltersEventHandlers = true
		}
	} else if strings.Contains(body, "o_nerror") || strings.Contains(body, "on_error") {
		p.FiltersEventHandlers = true
	}

	// Keyword filters.
	if !strings.Contains(body, "alert(") {
		p.FiltersKeywords["alert("] = true
	}
	if !strings.Contains(strings.ToLower(body), "javascript:") {
		p.FiltersKeywords["javascript:"] = true
	}

	return p
}

// EffectivePayloadClass reports whether payloads containing angle brackets
// survive the server filter.
func (p *FilterProfile) AllowsAngleBrackets() bool {
	return !p.StripsAngleBrackets && !p.EncodesAngleBrackets
}

// EffectivePayloadClass reports whether quote-breakout payloads survive.
func (p *FilterProfile) AllowsQuotes() bool {
	return !p.EncodesQuotes
}
