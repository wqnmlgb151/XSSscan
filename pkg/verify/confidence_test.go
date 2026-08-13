package verify

import (
	"math"
	"testing"
)

func TestScoreAllPositiveFactors(t *testing.T) {
	cs := NewConfidenceScorer()
	f := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
		CSPWeak:        true,
	}
	score := cs.Score(f)

	// All positive factors cap at MaxUnverifiedConfidence (0.90) — 1.0 is
	// reserved for browser-execution-verified findings.
	if math.Abs(score-MaxUnverifiedConfidence) > 0.001 {
		t.Errorf("Expected %.2f with all positive factors, got %.2f", MaxUnverifiedConfidence, score)
	}
}

func TestScoreWAFPenaltyDoesNotDropBelowThreshold(t *testing.T) {
	cs := NewConfidenceScorer()
	// A real finding: reflected, context break, valid syntax, no sanitization
	// but WAF is detected — the interaction effect reduces NoSanitization weight
	// from 0.25 to 0.075, then the multiplicative WAF penalty (0.9) applies.
	f := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
		WAFBlocked:     true,
	}
	score := cs.Score(f)

	// Score = (0.25 + 0.25 + 0.15 + 0.075) * 0.9 = 0.725 * 0.9 = 0.6525
	expected := 0.6525
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("Expected %.4f, got %.4f", expected, score)
	}
	if score < DefaultConfidenceThreshold {
		t.Errorf("WAF interaction should still allow above-threshold: got %.4f", score)
	}
}

func TestScoreWithLengthLimitedAndWAF(t *testing.T) {
	cs := NewConfidenceScorer()
	// Worst case: WAF + LengthLimited with all positive factors
	f := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
		WAFBlocked:     true,
		LengthLimited:  true,
	}
	score := cs.Score(f)

	// Score = (0.25 + 0.25 + 0.15 + 0.075) * 0.9 * 0.9 = 0.725 * 0.81 = 0.58725
	expected := 0.58725
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("Expected %.4f, got %.4f", expected, score)
	}
	if score < 0.40 {
		t.Errorf("Combined penalties too severe: score %.4f should be >= 0.40", score)
	}
}

func TestScoreMinimumIsZero(t *testing.T) {
	cs := NewConfidenceScorer()
	// No positive factors, only penalties
	f := Factors{
		Reflected:     false,
		WAFBlocked:    true,
		LengthLimited: true,
	}
	score := cs.Score(f)

	if score != 0.0 {
		t.Errorf("Expected 0.0 with no positive factors, got %.2f", score)
	}
}

func TestScoreReflectedAndContextBreakOnly(t *testing.T) {
	cs := NewConfidenceScorer()
	// ContextBreak without SyntaxValid: interaction effect applies
	f := Factors{
		Reflected:    true,
		ContextBreak: true,
	}
	score := cs.Score(f)

	// Score = 0.25 + (0.25 * 0.4) = 0.25 + 0.10 = 0.35
	expected := 0.35
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("Expected %.2f for reflected+contextBreak (invalid syntax), got %.4f", expected, score)
	}
}

func TestScoreReflectedOnly(t *testing.T) {
	cs := NewConfidenceScorer()
	// Only reflected, nothing else
	f := Factors{
		Reflected: true,
	}
	score := cs.Score(f)

	if math.Abs(score-0.25) > 0.001 {
		t.Errorf("Expected 0.25 for reflected-only, got %.2f", score)
	}
}

// TestScoreContextBreakWithValidSyntax verifies that ContextBreak gets full
// credit when the payload also has valid syntax (no interaction penalty).
func TestScoreContextBreakWithValidSyntax(t *testing.T) {
	cs := NewConfidenceScorer()
	f := Factors{
		Reflected:    true,
		ContextBreak: true,
		SyntaxValid:  true,
	}
	score := cs.Score(f)

	// Score = 0.25 + 0.25 + 0.15 = 0.65 (no interaction discount)
	expected := 0.65
	if math.Abs(score-expected) > 0.001 {
		t.Errorf("Expected %.2f for reflected+contextBreak+syntaxValid, got %.4f", expected, score)
	}
}

// TestScoreNoSanitizationWithWAF verifies the WAF interaction: NoSanitization
// gets discounted when WAF is present, because the WAF is effectively filtering.
func TestScoreNoSanitizationWithWAF(t *testing.T) {
	cs := NewConfidenceScorer()

	// Without WAF: full NoSanitization credit
	noWAF := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
	}
	scoreNoWAF := cs.Score(noWAF)

	// With WAF: NoSanitization discounted
	withWAF := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
		WAFBlocked:     true,
	}
	scoreWAF := cs.Score(withWAF)

	// WAF-blocked score must be lower than non-WAF
	if scoreWAF >= scoreNoWAF {
		t.Errorf("WAF should reduce score: WAF=%.4f vs noWAF=%.4f", scoreWAF, scoreNoWAF)
	}

	// Without WAF: (0.25+0.25+0.15+0.25) = 0.90
	if math.Abs(scoreNoWAF-0.90) > 0.001 {
		t.Errorf("Expected 0.90 without WAF, got %.4f", scoreNoWAF)
	}

	// With WAF: (0.25+0.25+0.15+0.075) * 0.9 = 0.6525
	if math.Abs(scoreWAF-0.6525) > 0.001 {
		t.Errorf("Expected 0.6525 with WAF interaction, got %.4f", scoreWAF)
	}
}

// TestScoreInteractionCompounding verifies that multiple negative interactions
// compound properly: WAFBlocked + SyntaxValid=false should produce a much
// lower score than either alone.
func TestScoreInteractionCompounding(t *testing.T) {
	cs := NewConfidenceScorer()

	// Baseline: all positive factors
	baseline := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
	}
	scoreBaseline := cs.Score(baseline) // 1.0

	// Only WAFBlocked (SyntaxValid=true, NoSanitization=true)
	onlyWAF := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
		WAFBlocked:     true,
	}
	scoreOnlyWAF := cs.Score(onlyWAF) // (0.25+0.25+0.15+0.075)*0.9 = 0.6525

	// Only invalid syntax (WAFBlocked=false)
	onlyInvalid := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    false,
		NoSanitization: true,
	}
	scoreOnlyInvalid := cs.Score(onlyInvalid) // 0.25+0.10+0.25 = 0.60

	// Both negative interactions + WAF penalty
	both := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    false,
		NoSanitization: true,
		WAFBlocked:     true,
	}
	scoreBoth := cs.Score(both) // (0.25+0.10+0.075)*0.9 = 0.3825

	// Combined should be worse than either alone
	if scoreBoth >= scoreOnlyWAF {
		t.Errorf("Combined (%.4f) should be worse than WAF-only (%.4f)", scoreBoth, scoreOnlyWAF)
	}
	if scoreBoth >= scoreOnlyInvalid {
		t.Errorf("Combined (%.4f) should be worse than invalid-only (%.4f)", scoreBoth, scoreOnlyInvalid)
	}
	if scoreBoth >= scoreBaseline {
		t.Errorf("Combined (%.4f) should be worse than baseline (%.4f)", scoreBoth, scoreBaseline)
	}

	// All scores should be strictly ordered
	if !(scoreBaseline > scoreOnlyWAF && scoreOnlyWAF > scoreBoth) {
		t.Errorf("Expected strict ordering: baseline=%.4f > onlyWAF=%.4f > both=%.4f",
			scoreBaseline, scoreOnlyWAF, scoreBoth)
	}
	if !(scoreBaseline > scoreOnlyInvalid && scoreOnlyInvalid > scoreBoth) {
		t.Errorf("Expected strict ordering: baseline=%.4f > onlyInvalid=%.4f > both=%.4f",
			scoreBaseline, scoreOnlyInvalid, scoreBoth)
	}
}

// TestScorePenaltiesAreMultiplicative verifies that two penalties compound
// multiplicatively (0.9 * 0.9 = 0.81) rather than additively (1 - 0.2 = 0.8).
func TestScorePenaltiesAreMultiplicative(t *testing.T) {
	cs := NewConfidenceScorer()

	// No penalties
	noPenalty := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
	}
	scoreNoPenalty := cs.Score(noPenalty) // 0.90 (no CSP)

	// Both penalties (WAFBlocked=true means NoSanitization is also discounted)
	bothPenalties := Factors{
		Reflected:      true,
		ContextBreak:   true,
		SyntaxValid:    true,
		NoSanitization: true,
		WAFBlocked:     true,
		LengthLimited:  true,
	}
	scoreBoth := cs.Score(bothPenalties)

	// WAF interaction: NoSanitization weight drops from 0.25 to 0.075
	// Score = (0.25 + 0.25 + 0.15 + 0.075) * 0.9 * 0.9 = 0.725 * 0.81 = 0.5873
	expected := 0.725 * 0.9 * 0.9
	if math.Abs(scoreBoth-expected) > 0.001 {
		t.Errorf("Expected multiplicative penalty %.4f, got %.4f", expected, scoreBoth)
	}

	// Verify it's NOT additive: additive would give 0.725 * 0.8 = 0.58
	additive := 0.725 * (1.0 - 0.10 - 0.10)
	if math.Abs(scoreBoth-additive) < 0.005 {
		t.Errorf("Penalties appear additive (%.4f) not multiplicative (%.4f)", additive, scoreBoth)
	}

	// Verify multiplicative: 0.725 * 0.81 = 0.58725
	multiplicative := 0.725 * 0.9 * 0.9
	if math.Abs(scoreBoth-multiplicative) > 0.001 {
		t.Errorf("Expected multiplicative %.4f, got %.4f", multiplicative, scoreBoth)
	}

	_ = scoreNoPenalty // used for relative comparison
}

// TestScoreOrderingInvariant verifies the monotonicity property: adding more
// negative signals (penalties or interaction effects) never increases the score.
// This is the fundamental regression guard for the scoring model — if a future
// change breaks monotonicity, findings could be over-ranked.
func TestScoreOrderingInvariant(t *testing.T) {
	cs := NewConfidenceScorer()

	// Best case: all positive factors, no penalties, no WAF
	perfect := cs.Score(Factors{
		Reflected: true, ContextBreak: true, SyntaxValid: true,
		NoSanitization: true, CSPWeak: true,
	}) // 1.0

	// Single length penalty (multiplicative 0.9, applied after the 0.90 cap)
	withLength := cs.Score(Factors{
		Reflected: true, ContextBreak: true, SyntaxValid: true,
		NoSanitization: true, CSPWeak: true, LengthLimited: true,
	}) // 0.9 (capped) * 0.9 = 0.81

	// WAF penalty + interaction (NoSanitization discounted to 0.075, then ×0.9)
	withWAF := cs.Score(Factors{
		Reflected: true, ContextBreak: true, SyntaxValid: true,
		NoSanitization: true, CSPWeak: true, WAFBlocked: true,
	}) // (0.25+0.25+0.15+0.075+0.10) * 0.9 = 0.7425

	// Both penalties + WAF interaction
	withBoth := cs.Score(Factors{
		Reflected: true, ContextBreak: true, SyntaxValid: true,
		NoSanitization: true, CSPWeak: true,
		WAFBlocked: true, LengthLimited: true,
	}) // 0.825 * 0.9 * 0.9 = 0.66825

	// Monotonic chain: each strictly worse configuration scores lower
	if !(perfect > withLength) {
		t.Errorf("perfect (%.4f) must exceed length-penalty (%.4f)", perfect, withLength)
	}
	if !(withLength > withWAF) {
		t.Errorf("length-penalty (%.4f) must exceed WAF (%.4f)", withLength, withWAF)
	}
	if !(withWAF > withBoth) {
		t.Errorf("WAF (%.4f) must exceed both-penalties (%.4f)", withWAF, withBoth)
	}
}

// TestScoreNeverExceeds1 verifies the upper bound invariant: no combination of
// factors can produce a score above 1.0, even with all positive signals active.
func TestScoreNeverExceeds1(t *testing.T) {
	cs := NewConfidenceScorer()

	// All positive factors active — this is the theoretical maximum.
	score := cs.Score(Factors{
		Reflected: true, ContextBreak: true, SyntaxValid: true,
		NoSanitization: true, CSPWeak: true,
	})
	if score > 1.0 {
		t.Errorf("Score %.6f exceeds 1.0 — clamping invariant broken", score)
	}
	// Unverified findings cap at MaxUnverifiedConfidence; only execution
	// verification (+0.15 in the engine) can reach 1.0.
	if math.Abs(score-MaxUnverifiedConfidence) > 0.001 {
		t.Errorf("All-positive score should be exactly %.2f, got %.6f", MaxUnverifiedConfidence, score)
	}
}

// TestScoreNeverBelow0 verifies the lower bound invariant: no combination of
// factors can produce a score below 0.0, even with all penalties active.
func TestScoreNeverBelow0(t *testing.T) {
	cs := NewConfidenceScorer()

	// No positive factors, no penalties — baseline zero.
	scoreZero := cs.Score(Factors{})
	if scoreZero != 0.0 {
		t.Errorf("Empty factors should score 0.0, got %.6f", scoreZero)
	}

	// All penalties active with no positive signals — still must be >= 0.
	scorePenalties := cs.Score(Factors{WAFBlocked: true, LengthLimited: true})
	if scorePenalties < 0.0 {
		t.Errorf("Score %.6f below 0.0 — clamping invariant broken", scorePenalties)
	}
	if scorePenalties != 0.0 {
		t.Errorf("Penalties with no positives should score 0.0, got %.6f", scorePenalties)
	}
}

// TestScoreNearThreshold verifies there are no cliff-edge discontinuities around
// the 0.60 reporting threshold. Small changes in input factors should produce
// small changes in score (bounded by the largest single weight).
func TestScoreNearThreshold(t *testing.T) {
	cs := NewConfidenceScorer()

	tests := []struct {
		name   string
		f      Factors
		expect float64
	}{
		{
			// 0.25 (reflected) + 0.10 (contextBreak × 0.4) + 0.25 (noSanitization) = 0.60
			name:   "at_threshold",
			f:      Factors{Reflected: true, ContextBreak: true, NoSanitization: true},
			expect: 0.60,
		},
		{
			// 0.25 + 0.25 (contextBreak) + 0.15 (syntaxValid) = 0.65
			name:   "just_above_threshold",
			f:      Factors{Reflected: true, ContextBreak: true, SyntaxValid: true},
			expect: 0.65,
		},
		{
			// 0.25 + 0.25 (noSanitization) = 0.50
			name:   "just_below_threshold",
			f:      Factors{Reflected: true, NoSanitization: true},
			expect: 0.50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := cs.Score(tt.f)
			if math.Abs(score-tt.expect) > 0.001 {
				t.Errorf("Expected %.4f, got %.4f", tt.expect, score)
			}
		})
	}

	// No cliff-edge: verify that transitions near the threshold are smooth.
	// The largest possible single-factor change is weightContextBreak (0.25),
	// so no step across the threshold should exceed that.
	below := cs.Score(Factors{Reflected: true, NoSanitization: true})                  // 0.50
	at := cs.Score(Factors{Reflected: true, ContextBreak: true, NoSanitization: true}) // 0.60
	above := cs.Score(Factors{Reflected: true, ContextBreak: true, SyntaxValid: true}) // 0.65

	maxSingleChange := weightContextBreak // 0.25 — the largest single weight

	if jump := at - below; jump > maxSingleChange+0.001 {
		t.Errorf("Cliff-edge: below→at jump %.4f exceeds max single factor %.2f", jump, maxSingleChange)
	}
	if jump := above - at; jump > maxSingleChange+0.001 {
		t.Errorf("Cliff-edge: at→above jump %.4f exceeds max single factor %.2f", jump, maxSingleChange)
	}

	// Verify threshold classification: below < threshold <= above
	if below >= DefaultConfidenceThreshold {
		t.Errorf("below-threshold score %.4f incorrectly at/above threshold", below)
	}
	if above <= DefaultConfidenceThreshold {
		t.Errorf("above-threshold score %.4f incorrectly at/below threshold", above)
	}
}

// TestScoreClampedToZeroOne verifies the score is always in [0.0, 1.0].
func TestScoreClampedToZeroOne(t *testing.T) {
	cs := NewConfidenceScorer()

	tests := []struct {
		name  string
		f     Factors
		minOk float64
		maxOk float64
	}{
		{"all_true", Factors{true, true, true, true, false, true, false}, 0.0, MaxUnverifiedConfidence},
		{"all_false", Factors{false, false, false, false, false, false, false}, 0.0, 0.0},
		{"all_penalties", Factors{false, false, false, false, true, false, true}, 0.0, 0.0},
		{"only_positive", Factors{true, true, true, true, false, true, false}, MaxUnverifiedConfidence, MaxUnverifiedConfidence},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := cs.Score(tt.f)
			if s < tt.minOk || s > tt.maxOk {
				t.Errorf("Score %.4f not in [%.1f, %.1f]", s, tt.minOk, tt.maxOk)
			}
		})
	}
}
