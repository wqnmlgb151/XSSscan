package verify

import (
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/analyze"
	"github.com/xsscan/xsscan/pkg/context"
)

// Phase 1.1: partialMatch correctly handles entity-encoded tags
func TestPartialMatchEntityEncodedTag(t *testing.T) {
	v := NewVerifier()
	// Body has entity-encoded tag, raw tag NOT present → sanitized, not reflected
	body := `<div>&lt;img src=x onerror=alert(1)&gt;</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to return false for entity-encoded-only tag (sanitized)")
	}
}

func TestPartialMatchCoreTextPresent(t *testing.T) {
	v := NewVerifier()
	// Body has the full payload reflected — partialMatch is only called when
	// the full payload is NOT found. Test with a payload whose core text
	// (after tag stripping) is a substantial portion of the original.
	body := `<div>user_input_here</div>`
	payload := `<b>user_input_here</b>`

	// Strip tags → "user_input_here" (15 chars) / payload (24 chars) ≈ 0.625 > 0.4
	result := v.partialMatch(strings.ToLower(body), body, payload)
	if !result {
		t.Error("Expected partialMatch to return true when core text content is present")
	}
}


func TestPartialMatchNotReflectedAtAll(t *testing.T) {
	v := NewVerifier()
	body := `<div>Hello World</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to return false when payload not in body at all")
	}
}

func TestPartialMatchCaseInsensitiveEntityCheck(t *testing.T) {
	v := NewVerifier()
	// Uppercase entity-encoded tag should also be detected as sanitized
	body := `<div>&lt;IMG src=x onerror=alert(1)&gt;</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to handle case-insensitive entity-encoded tags")
	}
}

func TestDetectSanitizationEventFilteredButOtherHandlersPresent(t *testing.T) {
	v := NewVerifier()

	// Scenario: payload is just an event handler value (no HTML tags to strip),
	// server removed it, but page has other onclick handlers elsewhere.
	// The bug: v.eventFilter.MatchString(body) returns true because of unrelated
	// handlers, so sanitization is NOT detected even though it should be.
	body := `<html><body><input type="text"><button onclick="submit()">OK</button></body></html>`
	payload := `onerror=alert(1)`

	// payload NOT found verbatim in body (it was removed/filtered)
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (event handler removed), but got false — other event handlers in body masked the detection")
	}
}

func TestDetectSanitizationIntactPayloadWithOtherHandlers(t *testing.T) {
	v := NewVerifier()

	// Scenario: payload reflected as-is, page has other event handlers
	body := `<html><body><div onerror=alert(1)><button onclick="submit()">OK</button></body></html>`
	payload := `onerror=alert(1)`

	// payload IS found verbatim in body
	result := v.detectSanitization(strings.ToLower(body), body, payload, true)
	if result {
		t.Error("Expected no sanitization (payload present), but got true")
	}
}

func TestDetectSanitizationHTMLEntityEncoding(t *testing.T) {
	v := NewVerifier()

	// Payload is HTML-entity-encoded in response
	body := `<html><body>&lt;img src=x onerror=alert(1)&gt;</body></html>`
	payload := `<img src=x onerror=alert(1)>`

	// payload NOT found verbatim (entity-encoded)
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (HTML entity encoding), but got false")
	}
}

func TestDetectSanitizationTagStripping(t *testing.T) {
	v := NewVerifier()

	// Server strips tags but keeps text
	body := `<html><body>alert(1)</body></html>`
	payload := `<img src=x onerror=alert(1)>`

	// payload NOT found verbatim (tags stripped)
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (tag stripping), but got false")
	}
}

func TestDetectSanitizationPartialEncoding(t *testing.T) {
	v := NewVerifier()

	// Server only escapes < but not >
	body := `<html><body>&lt;img src=x onerror=alert(1)></body></html>`
	payload := `<img src=x onerror=alert(1)>`

	// payload NOT found verbatim (partial encoding)
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (partial encoding), but got false")
	}
}

func TestDetectSanitizationNotPresent(t *testing.T) {
	v := NewVerifier()

	// Payload reflected as-is, no other event handlers
	body := `<html><body><img src=x onerror=alert(1)></body></html>`
	payload := `<img src=x onerror=alert(1)>`

	// payload IS found verbatim in body
	result := v.detectSanitization(strings.ToLower(body), body, payload, true)
	if result {
		t.Error("Expected no sanitization (payload intact), but got true")
	}
}

// ============================================================================
// Phase 2: partialMatch boundary conditions
// ============================================================================

func TestPartialMatchShortPayload(t *testing.T) {
	v := NewVerifier()
	// Payloads shorter than minPayloadLen (8) always return false
	body := `<div>abc</div>`
	payload := `<img x>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to return false for payload < 8 chars")
	}
}

func TestPartialMatchTagHeavyPayload(t *testing.T) {
	v := NewVerifier()
	// Tag-heavy payload where stripped core < 40% of original → false
	// Payload: <img src=x onerror=alert(1)> (28 chars)
	// Core after stripping: srcxonerroralert1 (19 chars) → 19/28 ≈ 0.679
	// Need something with higher tag ratio. Let's use a payload where most is inside tags.
	// <svg><script>alert(1)</script></svg> = 35 chars
	// Core: alert(1) = 7 chars → 7/35 = 0.2 < 0.4
	body := `<div>some unrelated content here</div>`
	payload := `<svg><script>alert(1)</script></svg>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to return false when stripped core < 40% of original")
	}
}

func TestPartialMatchExactly8Chars(t *testing.T) {
	v := NewVerifier()
	// Payload exactly 8 chars with a tag: <img xxx (8 chars)
	// Core after stripping: "xxx" (3 chars) → 3 < minPayloadLen(8) → false
	payload := `<img xxx`
	body := `<div>xxx</div>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to return false for 8-char payload with small core")
	}

	// Payload > 8 chars where core is exactly 8 chars (meets minPayloadLen):
	// <b>longtext = 11 chars, core = "longtext" (8 chars), 8/11 ≈ 0.727 > 0.4
	payload2 := `<b>longtext`
	body2 := `<div>longtext</div>`

	result2 := v.partialMatch(strings.ToLower(body2), body2, payload2)
	if !result2 {
		t.Error("Expected partialMatch to return true for payload with 8-char core")
	}
}

func TestPartialMatchNumericEntityEncoded(t *testing.T) {
	v := NewVerifier()
	// Tag encoded as numeric entity (&#60; for <) → sanitized, not reflected
	body := `<div>&#60;img src=x onerror=alert(1)&#62;</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.partialMatch(strings.ToLower(body), body, payload)
	if result {
		t.Error("Expected partialMatch to return false for numeric-entity-encoded tag")
	}
}

// ============================================================================
// Phase 2: checkContextBreak — CSP interaction
// ============================================================================

func TestCheckContextBreakStrongCSPNoBypass(t *testing.T) {
	// Strong CSP with no bypasses prevents exploitation even in exploitable context
	csp := &analyze.CSPPolicy{
		Score:    analyze.CSPScore{Value: 80, Level: "strong"},
		Bypasses: []analyze.CSPBypass{},
	}

	result := checkContextBreak(context.ContextHTMLBody, csp)
	if result {
		t.Error("Expected checkContextBreak to return false for strong CSP with no bypass")
	}
}

func TestCheckContextBreakStrongCSPWithBypass(t *testing.T) {
	// Strong CSP but with a bypass → still exploitable
	csp := &analyze.CSPPolicy{
		Score:    analyze.CSPScore{Value: 80, Level: "strong"},
		Bypasses: []analyze.CSPBypass{{Type: "jsonp", Description: "test"}},
	}

	result := checkContextBreak(context.ContextHTMLBody, csp)
	if !result {
		t.Error("Expected checkContextBreak to return true for strong CSP with bypass")
	}
}

func TestCheckContextBreakNonExploitableContexts(t *testing.T) {
	// Non-exploitable contexts: CSS block, entity, comment, etc.
	nonExploitable := []context.ContextType{
		context.ContextCSSBlock,
		context.ContextHTMLEntity,
		context.ContextHTMLComment,
		context.ContextCSSValue,
		context.ContextUnknown,
	}

	csp := &analyze.CSPPolicy{
		Score:    analyze.CSPScore{Value: 80, Level: "strong"},
		Bypasses: []analyze.CSPBypass{},
	}

	for _, ctx := range nonExploitable {
		result := checkContextBreak(ctx, csp)
		if result {
			t.Errorf("Expected checkContextBreak to return false for non-exploitable context %v", ctx)
		}
	}
}

func TestCheckContextBreakNoCSPDependsOnContext(t *testing.T) {
	// No CSP → result depends only on context type
	tests := []struct {
		ctxType context.ContextType
		want    bool
	}{
		{context.ContextHTMLBody, true},
		{context.ContextJSBlock, true},
		{context.ContextJSString, true},
		{context.ContextURLAttr, true},
		{context.ContextSVGContainer, true},
		{context.ContextCSSBlock, false},
		{context.ContextHTMLEntity, false},
		{context.ContextHTMLComment, false},
		{context.ContextUnknown, false},
	}

	for _, tt := range tests {
		result := checkContextBreak(tt.ctxType, nil)
		if result != tt.want {
			t.Errorf("checkContextBreak(%v, nil) = %v, want %v", tt.ctxType, result, tt.want)
		}
	}
}

func TestCheckContextBreakModerateCSP(t *testing.T) {
	// Moderate CSP should NOT block context break (only "strong" with no bypasses blocks)
	csp := &analyze.CSPPolicy{
		Score:    analyze.CSPScore{Value: 65, Level: "moderate"},
		Bypasses: []analyze.CSPBypass{},
	}

	result := checkContextBreak(context.ContextHTMLBody, csp)
	if !result {
		t.Error("Expected checkContextBreak to return true for moderate CSP")
	}
}

// ============================================================================
// Phase 2: checkSyntaxValidity — edge cases
// ============================================================================

func TestCheckSyntaxValidityNumericEntities(t *testing.T) {
	v := NewVerifier()
	// Payload found as numeric entities → valid
	body := `<div>&#60;img src=x onerror=alert(1)&#62;</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.checkSyntaxValidity(body, payload)
	if !result {
		t.Error("Expected checkSyntaxValidity to return true for numeric-entity-encoded payload")
	}
}

func TestCheckSyntaxValidityPartialEncoding(t *testing.T) {
	v := NewVerifier()
	// Only < and > escaped → valid (partialEncoder replaces both < and >)
	body := `<div>&lt;img src=x onerror=alert(1)&gt;</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.checkSyntaxValidity(body, payload)
	if !result {
		t.Error("Expected checkSyntaxValidity to return true for partial encoding (< > escaped)")
	}
}

func TestCheckSyntaxValidityCorruptedTag(t *testing.T) {
	v := NewVerifier()
	// Tag name corrupted in response (e.g., space after <) → invalid
	body := `<div>< img src=x onerror=alert(1)></div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.checkSyntaxValidity(body, payload)
	if result {
		t.Error("Expected checkSyntaxValidity to return false for corrupted tag name")
	}
}

func TestCheckSyntaxValidityOddQuotes(t *testing.T) {
	v := NewVerifier()
	// Odd number of double quotes → invalid
	body := `<div><img src="x" onerror="alert(1)></div>`
	payload := `<img src="x" onerror="alert(1)>`

	result := v.checkSyntaxValidity(body, payload)
	if result {
		t.Error("Expected checkSyntaxValidity to return false for odd number of quotes")
	}
}

func TestCheckSyntaxValidityOddSingleQuotes(t *testing.T) {
	v := NewVerifier()
	// Odd number of single quotes → invalid
	body := `<div><img src='x' onerror='alert(1)></div>`
	payload := `<img src='x' onerror='alert(1)>`

	result := v.checkSyntaxValidity(body, payload)
	if result {
		t.Error("Expected checkSyntaxValidity to return false for odd number of single quotes")
	}
}

func TestCheckSyntaxValidityNoAngleBrackets(t *testing.T) {
	v := NewVerifier()
	// Payload without angle brackets → always valid
	body := `<div>alert(1)</div>`
	payload := `alert(1)`

	result := v.checkSyntaxValidity(body, payload)
	if !result {
		t.Error("Expected checkSyntaxValidity to return true for payload without angle brackets")
	}
}

func TestCheckSyntaxValidityBalancedBrackets(t *testing.T) {
	v := NewVerifier()
	// Balanced angle brackets, valid tag, balanced quotes → valid
	body := `<div><img src="x" onerror="alert(1)"></div>`
	payload := `<img src="x" onerror="alert(1)">`

	result := v.checkSyntaxValidity(body, payload)
	if !result {
		t.Error("Expected checkSyntaxValidity to return true for well-formed payload")
	}
}

func TestCheckSyntaxValidityPayloadAbsent(t *testing.T) {
	v := NewVerifier()
	// Payload completely absent and not entity-encoded → invalid
	body := `<div>Hello World</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.checkSyntaxValidity(body, payload)
	if result {
		t.Error("Expected checkSyntaxValidity to return false for absent payload")
	}
}

// ============================================================================
// Phase 2: checkLengthLimited — boundary conditions
// ============================================================================

func TestCheckLengthLimitedExactly75Percent(t *testing.T) {
	v := NewVerifier()
	// Payload prefix at exactly 75% match
	payload := `<img src=x onerror=alert(1)>` // 28 chars, 75% = 21
	body := `<div><img src=x onerror=alert(1)</div>` // truncated at 21 chars

	result := v.checkLengthLimited(body, payload)
	if !result {
		t.Error("Expected checkLengthLimited to return true for 75% prefix match")
	}
}

func TestCheckLengthLimitedShortPayload10CharPrefix(t *testing.T) {
	v := NewVerifier()
	// Short payload (e.g., 12 chars): prefixLen = min(12, max(10, 12*3/4=9)) = 10
	payload := `<img src=x>` // 12 chars
	body := `<div><img src=x</div>` // 10-char prefix found

	result := v.checkLengthLimited(body, payload)
	if !result {
		t.Error("Expected checkLengthLimited to return true for 10-char prefix match on short payload")
	}
}

func TestCheckLengthLimitedFullPayloadFound(t *testing.T) {
	v := NewVerifier()
	// Full payload found → not length limited
	payload := `<img src=x onerror=alert(1)>`
	body := `<div><img src=x onerror=alert(1)></div>`

	result := v.checkLengthLimited(body, payload)
	if result {
		t.Error("Expected checkLengthLimited to return false when full payload is found")
	}
}

func TestCheckLengthLimitedNeitherFullNorPrefix(t *testing.T) {
	v := NewVerifier()
	// Neither full payload nor sufficient prefix found → not length limited
	payload := `<img src=x onerror=alert(1)>` // 28 chars, need 75% = 21
	body := `<div>totally unrelated content here</div>`

	result := v.checkLengthLimited(body, payload)
	if result {
		t.Error("Expected checkLengthLimited to return false when neither full nor prefix found")
	}
}

func TestCheckLengthLimitedJustBelowThreshold(t *testing.T) {
	v := NewVerifier()
	// Payload 28 chars, 75% = 21. If only 20 chars match → should be false
	payload := `<img src=x onerror=alert(1)>` // 28 chars
	// 20 chars: `<img src=x onerror=
	body := `<div><img src=x onerror=</div>`

	// Wait, this IS 20 chars which is less than 21. Let me recalculate.
	// prefixLen = min(28, 28*3/4=21) = 21
	// Since 21 >= 10, prefixLen stays 21
	// prefix = payload[:21] = `<img src=x onerror=a`
	// body contains `<img src=x onerror=` (20 chars) but NOT the 21-char prefix
	result := v.checkLengthLimited(body, payload)
	if result {
		t.Error("Expected checkLengthLimited to return false when prefix match is below 75% threshold")
	}
}

// ============================================================================
// Phase 2: detectSanitization — remaining edge cases
// ============================================================================

func TestDetectSanitizationNumericEntitiesNearPosition(t *testing.T) {
	v := NewVerifier()
	// Numeric entities for payload characters near where payload was expected
	body := `<div>&#60;img src=x onerror=alert(1)&#62;</div>`
	payload := `<img src=x onerror=alert(1)>`

	// payload NOT found verbatim (entity-encoded)
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (numeric entities near position)")
	}
}

func TestDetectSanitizationUnrelatedNumericEntities(t *testing.T) {
	v := NewVerifier()
	// Numeric entities for unrelated chars (em dash &#8212;) → not sanitized.
	// The body only contains &#8212; (em dash) which doesn't encode any payload character.
	// Payload has text outside tags so tag stripping doesn't produce empty string.
	body := `<div>Hello &#8212; World</div>`
	payload := `hello<img src=x>`

	// Trace: partial encoding not found, full escape not found,
	// numericEntityEncode not found in body,
	// nearby check: &#8212; is not in numericEntityMap for < > → false,
	// tag stripping: stripped="hello" (not in body case-sensitive),
	// no event handlers in payload → returns false
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if result {
		t.Error("Expected no sanitization for unrelated numeric entities (em dash)")
	}
}

func TestDetectSanitizationTagsRemovedTextKept(t *testing.T) {
	v := NewVerifier()
	// Tags removed but text kept → sanitized
	body := `<div>alert(1)</div>`
	payload := `<img src=x onerror=alert(1)>`

	// payload NOT found verbatim (tags stripped)
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (tags removed, text kept)")
	}
}

func TestDetectSanitizationEventHandlerRemoved(t *testing.T) {
	v := NewVerifier()
	// Event handler removed from payload → sanitized
	body := `<div><img src=x></div>`
	payload := `<img src=x onerror=alert(1)>`

	// payload NOT found verbatim
	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (event handler removed)")
	}
}

func TestDetectSanitizationNumericEntityHexForm(t *testing.T) {
	v := NewVerifier()
	// Payload encoded as hex numeric entities (&#x3C; for <)
	body := `<div>&#x3C;img src=x onerror=alert(1)&#x3E;</div>`
	payload := `<img src=x onerror=alert(1)>`

	result := v.detectSanitization(strings.ToLower(body), body, payload, false)
	if !result {
		t.Error("Expected sanitization detected (hex numeric entity encoding)")
	}
}
