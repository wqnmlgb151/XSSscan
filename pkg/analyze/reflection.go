package analyze

import (
	"html"
	"net/url"
	"strings"

	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
)

type ReflectionAnalyzer struct{}

func NewReflectionAnalyzer() *ReflectionAnalyzer {
	return &ReflectionAnalyzer{}
}

// FindReflections locates all occurrences of a parameter value in the response.
// Falls back to fuzzy matching (URL-encoded, HTML-entity-encoded, case-variant,
// partial/truncated match) when exact match finds nothing.
//
// The body and pre-computed URL-decoded variant are passed in by the caller
// so that multi-parameter analysis avoids redundant URL-decoding per parameter.
func (ra *ReflectionAnalyzer) FindReflections(body string, param model.Parameter, decodedBody ...string) []model.ReflectionInfo {
	value := param.Value
	if value == "" {
		return nil
	}

	// Exact match first (fast path)
	if refs := ra.findExact(body, value); len(refs) > 0 {
		return refs
	}

	// Fuzzy match: try common server-side transformations
	for _, variant := range generateMarkerVariants(value) {
		if refs := ra.findExact(body, variant); len(refs) > 0 {
			return refs
		}
	}

	// Try URL-decoding the body (server may have encoded only some chars)
	if len(decodedBody) > 0 && decodedBody[0] != "" {
		if refs := ra.findExact(decodedBody[0], value); len(refs) > 0 {
			return refs
		}
	} else if refs := ra.tryURLDecodeAttempt(body, value); len(refs) > 0 {
		return refs
	}

	// Partial match: detect truncated reflections (server truncated the marker)
	if refs := ra.findPartial(body, value); len(refs) > 0 {
		return refs
	}

	return nil
}

// minPartialMatchLen is the minimum prefix length for partial reflection detection.
// Markers are 12 chars, so 8 chars gives reasonable confidence without false positives.
const minPartialMatchLen = 8

// findPartial detects truncated reflections where the server kept a prefix of the marker.
func (ra *ReflectionAnalyzer) findPartial(body, value string) []model.ReflectionInfo {
	if len(value) <= minPartialMatchLen {
		return nil
	}
	prefix := value[:minPartialMatchLen]
	var reflections []model.ReflectionInfo
	searchStart := 0
	for {
		idx := strings.Index(body[searchStart:], prefix)
		if idx < 0 {
			break
		}
		absIdx := searchStart + idx
		// Only count as partial if the full marker does NOT appear here
		// (exact match would have already been found above)
		end := absIdx + len(value)
		if end > len(body) || body[absIdx:end] != value {
			reflections = append(reflections, model.ReflectionInfo{
				Offset:  absIdx,
				Length:  minPartialMatchLen,
				Snippet: text.Snippet(body, prefix, 100),
			})
		}
		searchStart = absIdx + len(prefix)
	}
	return reflections
}

func (ra *ReflectionAnalyzer) findExact(body, value string) []model.ReflectionInfo {
	var reflections []model.ReflectionInfo
	searchStart := 0
	for {
		idx := strings.Index(body[searchStart:], value)
		if idx < 0 {
			break
		}
		absIdx := searchStart + idx
		reflections = append(reflections, model.ReflectionInfo{
			Offset:  absIdx,
			Length:  len(value),
			Snippet: text.Snippet(body, value, 100),
		})
		searchStart = absIdx + len(value)
	}
	return reflections
}

// generateMarkerVariants produces common server-side transformations of a marker.
// Skips variants that would be identical to the original (e.g., alphanumeric markers
// don't change under URL/HTML encoding or case transformation).
func generateMarkerVariants(marker string) []string {
	var variants []string
	if strings.ContainsAny(marker, "%&<>\"'") {
		variants = append(variants, url.QueryEscape(marker))
		variants = append(variants, html.EscapeString(marker))
	}
	hasLower := strings.ContainsFunc(marker, isLower)
	hasUpper := strings.ContainsFunc(marker, isUpper)
	if hasLower {
		variants = append(variants, strings.ToUpper(marker))
	}
	if hasUpper {
		variants = append(variants, strings.ToLower(marker))
	}
	return variants
}

func isLower(r rune) bool { return r >= 'a' && r <= 'z' }
func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }

// tryURLDecodeAttempt tries to URL-decode the body and search for the marker.
// Servers may URL-encode only certain characters (e.g., < → %3C).
func (ra *ReflectionAnalyzer) tryURLDecodeAttempt(body, value string) []model.ReflectionInfo {
	if !strings.Contains(body, "%") {
		return nil // Skip if no percent-encoding present
	}
	if decoded, err := url.QueryUnescape(body); err == nil && decoded != body {
		if refs := ra.findExact(decoded, value); len(refs) > 0 {
			return refs
		}
	}
	return nil
}
