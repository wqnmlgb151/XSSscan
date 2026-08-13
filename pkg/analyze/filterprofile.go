package analyze

import (
	"strings"
)

// FilterProfile describes how the server transforms injected special
// characters — the XSStrike "filter discovery" idea. By sending one probe
// containing all metacharacters and comparing the reflection, the scanner
// knows which payload classes can survive, instead of blindly sending
// everything.
type FilterProfile struct {
	StripsAngleBrackets  bool // < > removed entirely
	EncodesAngleBrackets bool // < > → &lt; &gt;
	EncodesDoubleQuote   bool // " → &quot;
	EncodesSingleQuote   bool // ' → &#39;
}

// FilterProbeValue contains one occurrence of every metacharacter whose
// fate the profile needs to determine.
const FilterProbeValue = MarkerPrefix + `<>"'()=onerror=alert(javascript:`

// filterWindow is the body region around each probe reflection used for
// detection. Scanning the full response (up to 10MB) is wasteful and
// page markup elsewhere would false-positive entity checks.
const filterWindow = 2048

// DetectFilterProfile analyzes a response body containing the reflection of
// FilterProbeValue. A page can reflect the same input in MULTIPLE places
// with different escaping (e.g., escaped in body text, raw in an attribute) —
// detection therefore scans every reflection occurrence and reports the
// MOST PERMISSIVE behavior: a capability is only marked blocked when EVERY
// occurrence blocks it. This prevents pruning payloads that work against
// the raw reflection point. Returns nil if the probe value cannot be located.
func DetectFilterProfile(body string) *FilterProfile {
	angleRaw := false
	angleEncoded := false
	angleStrippedAll := true
	doubleRaw := false
	singleRaw := false
	anyOccurrence := false

	searchFrom := 0
	for {
		idx := strings.Index(body[searchFrom:], MarkerPrefix)
		if idx < 0 {
			break
		}
		idx += searchFrom
		anyOccurrence = true

		// Examine only the probe tail — the characters immediately after
		// the marker (up to ~32 chars). The windowed approach failed
		// because surrounding attribute delimiters polluted raw-quote
		// detection; the probe's own chars are unambiguous.
		end := idx + len(MarkerPrefix) + 32
		if end > len(body) {
			end = len(body)
		}
		fragment := body[idx+len(MarkerPrefix) : end]

		if strings.Contains(fragment, "<") || strings.Contains(fragment, ">") {
			angleRaw = true
		}
		if strings.Contains(fragment, "&lt;") || strings.Contains(fragment, "&gt;") {
			angleEncoded = true
		}
		if !angleRaw && !angleEncoded {
			angleStrippedAll = angleStrippedAll && true
		} else {
			angleStrippedAll = false
		}
		if strings.Contains(fragment, "\"") {
			doubleRaw = true
		}
		if strings.Contains(fragment, "'") {
			singleRaw = true
		}

		searchFrom = idx + len(MarkerPrefix)
	}

	if !anyOccurrence {
		return nil
	}

	p := &FilterProfile{}
	// Aggregate to the most permissive profile: a capability is blocked
	// only when no occurrence preserved it.
	if angleEncoded && !angleRaw {
		p.EncodesAngleBrackets = true
	}
	if angleStrippedAll && !angleRaw && !angleEncoded {
		p.StripsAngleBrackets = true
	}
	if !doubleRaw {
		p.EncodesDoubleQuote = true
	}
	if !singleRaw {
		p.EncodesSingleQuote = true
	}

	return p
}

// AllowsAngleBrackets reports whether payloads containing angle brackets
// survive the server filter.
func (p *FilterProfile) AllowsAngleBrackets() bool {
	return !p.StripsAngleBrackets && !p.EncodesAngleBrackets
}

// AllowsDoubleQuote reports whether double-quote breakout payloads survive.
func (p *FilterProfile) AllowsDoubleQuote() bool {
	return !p.EncodesDoubleQuote
}

// AllowsSingleQuote reports whether single-quote breakout payloads survive.
func (p *FilterProfile) AllowsSingleQuote() bool {
	return !p.EncodesSingleQuote
}
