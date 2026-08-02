package verify

import (
	"regexp"
	"strings"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/context"
	"github.com/xsscan/xsscan/pkg/internal/text"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/payload"
)

type Verifier struct {
	scorer      *ConfidenceScorer
	tagStripper *regexp.Regexp
	eventFilter *regexp.Regexp
}

// Pre-compiled regexes and replacers for hot paths
var tagStartRe = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)`)

// minPayloadLen is the shortest payload worth fuzzy-matching.
// Shorter strings have too many false-positive substring hits.
const minPayloadLen = 8

// minCoreRatio requires that the tag-stripped core text constitutes at least
// this fraction of the original payload, preventing short fragments from
// matching unrelated content.
const minCoreRatio = 0.4

var htmlEscaper = strings.NewReplacer(
	"<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;", "&", "&amp;",
)

// partialEncoder escapes only angle brackets (common server behavior)
var partialEncoder = strings.NewReplacer("<", "&lt;", ">", "&gt;")

type VerificationResult struct {
	Vulnerable bool           `json:"vulnerable"`
	Confidence float64        `json:"confidence"`
	Evidence   model.Evidence `json:"evidence"`
	Reason     string         `json:"reason"`
}

func NewVerifier() *Verifier {
	return &Verifier{
		scorer:      NewConfidenceScorer(),
		tagStripper: regexp.MustCompile(`<[^>]*>`),
		eventFilter: regexp.MustCompile(`on\w+\s*=`),
	}
}

func (v *Verifier) Verify(respBody, bodyLower string, p payload.Payload, injection model.InjectionPoint, csp *analyze.CSPPolicy, wafResult WAFResult) *VerificationResult {
	return v.VerifyWithThreshold(respBody, bodyLower, p, injection, csp, wafResult, DefaultConfidenceThreshold)
}

// VerifyWithThreshold uses a configurable minimum confidence threshold.
// bodyLower is the pre-computed lowercase response body (computed once by the caller).
func (v *Verifier) VerifyWithThreshold(respBody, bodyLower string, p payload.Payload, injection model.InjectionPoint, csp *analyze.CSPPolicy, wafResult WAFResult, threshold float64) *VerificationResult {
	result := &VerificationResult{Vulnerable: false, Confidence: 0}

	// verbatimFound is reused by detectSanitization to skip encoding checks
	// when the payload is already present unmodified.
	verbatimFound := strings.Contains(respBody, p.Value)
	partialFound := false
	if !verbatimFound {
		partialFound = v.partialMatch(bodyLower, respBody, p.Value)
	}
	if !verbatimFound && !partialFound {
		result.Reason = "Payload not found in response"
		return result
	}

	// Hard gate: non-exploitable contexts (title, textarea, comment, entity, css_block, etc.)
	// cannot execute scripts without a breakout prefix. Reporting them as vulnerable
	// wastes hunter time with false positives.
	if !checkContextBreak(p.Context, csp) {
		result.Reason = "Reflection in non-exploitable context"
		return result
	}

	sanitized := v.detectSanitization(bodyLower, respBody, p.Value, verbatimFound)
	syntaxValid := v.checkSyntaxValidity(respBody, p.Value)
	lengthLimited := v.checkLengthLimited(respBody, p.Value)

	factors := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    syntaxValid,
		NoSanitization: !sanitized,
		WAFBlocked:     wafResult.Detected,
		CSPWeak:        csp != nil && (csp.Score.Level == "weak" || csp.Score.Level == "bypassable"),
		LengthLimited:  lengthLimited,
	}
	confidence := v.scorer.Score(factors)

	result.Confidence = confidence
	result.Evidence = model.Evidence{
		Reflection: text.Snippet(respBody, p.Value, 80),
		Context:    p.Context.String(),
	}

	if confidence >= threshold {
		result.Vulnerable = true
		result.Reason = "Payload executed in exploitable context"
	} else {
		result.Vulnerable = false
		result.Reason = "Payload reflected but filtered or non-executable"
	}
	return result
}

func (v *Verifier) partialMatch(bodyLower, body, p string) bool {
	if len(p) < minPayloadLen {
		return false
	}
	if strings.Contains(p, "<") {
		matches := tagStartRe.FindStringSubmatch(p)
		if len(matches) > 1 {
			tagName := strings.ToLower(matches[1])
			hasUnescaped := strings.Contains(bodyLower, "<"+tagName)
			hasEscaped := strings.Contains(bodyLower, "&lt;"+tagName)
			// Also check numeric entities: &#60; &#x3C; &#x3c; etc.
			hasNumericEntity := numericEntityRe.MatchString(bodyLower) &&
				strings.Contains(bodyLower, tagName)
			// If tag is entity-encoded (named or numeric) and raw tag is NOT present → sanitized
			if (hasEscaped || hasNumericEntity) && !hasUnescaped {
				return false
			}
		}
	}
	core := v.tagStripper.ReplaceAllString(p, "")
	core = strings.TrimSpace(core)
	if len(core) < minPayloadLen {
		return false
	}
	// Require core to be a substantial fraction of the original payload
	if float64(len(core))/float64(len(p)) < minCoreRatio {
		return false
	}
	return strings.Contains(body, core)
}

// numericEntityRe matches HTML numeric entities like &#60; &#x3C; &#x3c;
var numericEntityRe = regexp.MustCompile(`&#x?[0-9a-fA-F]+;`)

// numericEntityMap maps special characters to their common numeric entity forms.
// Used to detect if a payload was sanitized via numeric entity encoding.
var numericEntityMap = map[rune][]string{
	'<': {"&#60;", "&#x3C;", "&#x3c;", "&#060;"},
	'>': {"&#62;", "&#x3E;", "&#x3e;", "&#062;"},
	'"': {"&#34;", "&#x22;", "&#034;"},
	'\'': {"&#39;", "&#x27;", "&#039;"},
	'&': {"&#38;", "&#x26;", "&#038;"},
}

// numericEntityEncodesPayload checks if the nearby text contains numeric entities
// that decode to characters from the payload. This avoids false positives from
// unrelated numeric entities (e.g., &#8212; for em dash) on the page.
func numericEntityEncodesPayload(nearby, payload string) bool {
	for _, ch := range payload {
		if entities, ok := numericEntityMap[ch]; ok {
			for _, entity := range entities {
				if strings.Contains(nearby, entity) {
					return true
				}
			}
		}
	}
	return false
}

// checkContextBreak reports whether the payload escaped into an exploitable context,
// considering both the context type and CSP policy.
func checkContextBreak(ctxType context.ContextType, csp *analyze.CSPPolicy) bool {
	if !ctxType.IsExploitableType() {
		return false
	}
	// Strong CSP with no bypasses prevents exploitation
	if csp != nil && csp.Score.Level == "strong" && len(csp.Bypasses) == 0 {
		return false
	}
	return true
}

func (v *Verifier) checkSyntaxValidity(body, p string) bool {
	if !strings.Contains(p, "<") || !strings.Contains(p, ">") {
		return true // non-HTML payloads are always "syntactically valid"
	}

	idx := strings.Index(body, p)
	if idx < 0 {
		// Payload not found verbatim — check if it was entity-encoded.
		// If neither verbatim nor encoded form is present, the payload
		// was removed entirely; it's NOT syntactically valid.
		encoded := numericEntityEncode(p)
		if strings.Contains(body, encoded) {
			return true // entity-encoded but structurally intact
		}
		// Check partial encoding (only < and > escaped)
		if strings.ContainsAny(p, "<>") {
			partial := partialEncoder.Replace(p)
			if strings.Contains(body, partial) {
				return true
			}
		}
		return false // payload completely absent — not valid
	}

	snippet := body[idx : idx+len(p)]

	// 1. Balanced angle brackets
	if strings.Count(snippet, "<") != strings.Count(snippet, ">") {
		return false
	}

	// 2. If payload has a tag name, verify it's not malformed in the response
	if tagMatches := tagStartRe.FindStringSubmatch(p); len(tagMatches) > 1 {
		tagName := strings.ToLower(tagMatches[1])
		// Tag should appear intact: <tagName or <tagName> or <tagName ...
		expected := "<" + tagName
		if !strings.Contains(strings.ToLower(snippet), expected) {
			// Tag was mangled (e.g., < img or <scriptx)
			return false
		}
	}

	// 3. Verify quote balance for attribute payloads
	singleQuotes := strings.Count(snippet, "'")
	doubleQuotes := strings.Count(snippet, "\"")
	if singleQuotes%2 != 0 || doubleQuotes%2 != 0 {
		return false
	}

	return true
}

// numericEntityEncode converts special chars to their HTML numeric entity forms.
func numericEntityEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&#60;")
		case '>':
			b.WriteString("&#62;")
		case '"':
			b.WriteString("&#34;")
		case '\'':
			b.WriteString("&#39;")
		case '&':
			b.WriteString("&#38;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkLengthLimited detects if the payload was truncated in the response.
// Uses the full payload prefix (not just 10 chars) to avoid false positives
// from short prefixes matching unrelated content.
func (v *Verifier) checkLengthLimited(body, p string) bool {
	if !strings.Contains(body, p) {
		// Full payload not found — check if a substantial prefix exists
		// (indicating truncation rather than unrelated content).
		// Require at least 10 chars or 75% of payload to avoid false positives
		// from short prefixes matching unrelated page content.
		prefixLen := min(len(p), len(p)*3/4) // need 75% of payload to match
		if prefixLen < 10 {
			prefixLen = min(len(p), 10)
		}
		prefix := p[:prefixLen]
		return strings.Contains(body, prefix)
	}
	return false
}

// detectSanitization checks if the payload was filtered/encoded by the server.
// payloadFound indicates whether the payload was found verbatim in the body
// (passed from caller to avoid redundant strings.Contains check).
func (v *Verifier) detectSanitization(bodyLower, body, p string, payloadFound bool) bool {
	if payloadFound {
		return false
	}

	// Check partial encoding (e.g., only < and > were escaped — common server behavior)
	if strings.ContainsAny(p, "<>") {
		partial := partialEncoder.Replace(p)
		if strings.Contains(body, partial) {
			return true
		}
	}

	// Check full HTML entity encoding
	escaped := htmlEscaper.Replace(p)
	if strings.Contains(body, escaped) {
		return true
	}

	// Check numeric entity encoding (e.g., &#60; &#x3C; &#x3c;)
	if strings.ContainsAny(p, "<>&\"'") {
		numericEncoded := numericEntityEncode(p)
		if strings.Contains(body, numericEncoded) {
			return true
		}
		// Check for payload-specific numeric entities NEAR where the payload was expected.
		// Only flag sanitization if the entities actually decode to payload chars
		// (e.g., &#60; for <, &#34; for "). This avoids false positives from
		// unrelated entities like &#8212; (em dash) elsewhere on the page.
		payloadIdx := strings.Index(body, p[:min(len(p), 8)])
		if payloadIdx < 0 {
			payloadIdx = 0
		}
		snStart := max(0, payloadIdx-300)
		snEnd := min(len(body), payloadIdx+len(p)+300)
		nearby := body[snStart:snEnd]
		if !strings.Contains(nearby, p) && numericEntityEncodesPayload(nearby, p) {
			return true
		}
	}

	// Check tag stripping
	stripped := v.tagStripper.ReplaceAllString(p, "")
	if stripped != p && strings.Contains(body, stripped) {
		return true
	}

	// Check event handler filtering (e.g., onerror removed from payload)
	handlerMatches := v.eventFilter.FindAllString(p, -1)
	for _, handler := range handlerMatches {
		if !strings.Contains(bodyLower, strings.ToLower(handler)) {
			return true
		}
	}

	return false
}

