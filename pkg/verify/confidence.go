package verify

// ConfidenceScorer calculates confidence scores for findings.
// Score ranges from 0.0 (definitely not exploitable) to 1.0 (definitely exploitable).
type ConfidenceScorer struct{}

const (
	weightReflected      = 0.25
	weightContextBreak   = 0.25
	weightSyntaxValid    = 0.15
	weightNoSanitization = 0.25
	weightCSPWeak        = 0.10

	penaltyLengthLimited = 0.10
	penaltyWAFBlocked    = 0.10

	// interactionContextBreakInvalidSyntax is the multiplier applied to the
	// ContextBreak weight when the payload does NOT have valid syntax.
	// An invalid payload cannot reliably claim context escape, so we discount
	// the signal heavily.
	interactionContextBreakInvalidSyntax = 0.4

	// interactionNoSanitizationWithWAF is the multiplier applied to the
	// NoSanitization weight when a WAF is detected and likely filtering.
	// A WAF that intercepts requests is effectively sanitizing input, so the
	// "no sanitization detected" claim becomes unreliable.
	interactionNoSanitizationWithWAF = 0.3

	// DefaultConfidenceThreshold is the minimum confidence to report a finding.
	DefaultConfidenceThreshold = 0.60
)

// Factors are the individual signals that contribute to confidence
type Factors struct {
	Reflected      bool // Payload was reflected in response
	ContextBreak   bool // Payload escaped its injection context
	SyntaxValid    bool // Payload maintains valid syntax
	NoSanitization bool // No filtering/encoding detected
	WAFBlocked     bool // WAF detected and likely blocking
	CSPWeak        bool // CSP is weak or bypassable
	LengthLimited  bool // Payload was truncated
}

func NewConfidenceScorer() *ConfidenceScorer {
	return &ConfidenceScorer{}
}

// Score calculates a confidence score from 0.0 to 1.0.
//
// The model uses additive positive weights (summing to 1.0) with two
// interaction effects that discount signals when contradicting evidence is
// present, then applies penalties as multiplicative factors:
//
//   - WAFBlocked → NoSanitization weight is multiplied by 0.3 (a WAF that
//     intercepts requests is effectively sanitizing input).
//   - SyntaxValid=false → ContextBreak weight is multiplied by 0.4 (an
//     invalid payload cannot reliably claim context escape).
//   - Penalties (LengthLimited, WAFBlocked) are applied as multiplicative
//     factors (0.9 each) rather than additive subtractions, so they scale
//     with the score instead of creating cliff-edge discontinuities.
//
// This prevents over-compensation where a single strong signal (e.g. NoSanitization)
// can mask the presence of a WAF, or where ContextBreak alone can push a
// syntactically-invalid payload above the reporting threshold.
func (cs *ConfidenceScorer) Score(f Factors) float64 {
	score := 0.0

	if f.Reflected {
		score += weightReflected
	}

	// ContextBreak: discounted when syntax is invalid, because a broken
	// payload cannot reliably claim it escaped the injection context.
	if f.ContextBreak {
		if f.SyntaxValid {
			score += weightContextBreak
		} else {
			score += weightContextBreak * interactionContextBreakInvalidSyntax
		}
	}

	if f.SyntaxValid {
		score += weightSyntaxValid
	}

	// NoSanitization: discounted when a WAF is detected, because the WAF is
	// effectively filtering/sanitizing input before it reaches the app.
	if f.NoSanitization {
		if f.WAFBlocked {
			score += weightNoSanitization * interactionNoSanitizationWithWAF
		} else {
			score += weightNoSanitization
		}
	}

	if f.CSPWeak {
		score += weightCSPWeak
	}

	// Penalties as multiplicative factors — scale with the score rather
	// than creating cliff-edge drops. Two penalties compound: 0.9 * 0.9 = 0.81.
	penaltyFactor := 1.0
	if f.LengthLimited {
		penaltyFactor *= (1.0 - penaltyLengthLimited)
	}
	if f.WAFBlocked {
		penaltyFactor *= (1.0 - penaltyWAFBlocked)
	}

	score *= penaltyFactor

	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}
