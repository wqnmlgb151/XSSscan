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
const FilterProbeValue = "xsscan<>\"'()=onerror=alert(javascript:"

// filterWindow is the body region around the probe reflection used for
// detection. Scanning the full response (up to 10MB) is wasteful and
// page markup elsewhere would false-positive entity checks.
const filterWindow = 2048

// DetectFilterProfile analyzes a response body containing the reflection of
// FilterProbeValue. Detection runs on a windowed slice around the reflection
// so unrelated page markup cannot skew the result. Returns nil if the probe
// value cannot be located.
func DetectFilterProfile(body string) *FilterProfile {
	idx := strings.Index(body, "xsscan")
	if idx < 0 {
		return nil
	}
	start := idx - filterWindow
	if start < 0 {
		start = 0
	}
	end := idx + filterWindow
	if end > len(body) {
		end = len(body)
	}
	window := body[start:end]

	p := &FilterProfile{}

	// Angle brackets: encoded vs stripped (only detectable within the
	// window — the raw body is full of page markup).
	switch {
	case strings.Contains(window, "&lt;") || strings.Contains(window, "&gt;"):
		p.EncodesAngleBrackets = true
	case !strings.Contains(window, "<") && !strings.Contains(window, ">"):
		p.StripsAngleBrackets = true
	}

	// Quotes: per-type encoding.
	if strings.Contains(window, "&quot;") || strings.Contains(window, "&#34;") {
		p.EncodesDoubleQuote = true
	}
	if strings.Contains(window, "&#39;") || strings.Contains(window, "&#x27;") {
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
