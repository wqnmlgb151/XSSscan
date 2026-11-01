package stored

import (
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

// The reported stored finding must be the strongest one, not the first one produced.
//
// Each display page is evaluated separately, so one injection point can yield results of
// different standing. An execution is a direct observation while a structural match is an
// inference about the response; ordering must reflect that rather than whichever page
// happened to be processed first.
func TestBetterStoredFindingPrefersExecution(t *testing.T) {
	structural := &model.Finding{Confidence: 0.90, ExecutionVerified: false}
	executed := &model.Finding{Confidence: 0.85, ExecutionVerified: true}

	// A weaker-looking but executed result must replace a higher-confidence inference.
	if !betterStoredFinding(executed, structural) {
		t.Error("an executed result did not replace a higher-confidence structural one")
	}
	// And an inference must never displace an execution, however confident it looks.
	if betterStoredFinding(structural, executed) {
		t.Error("a structural result displaced an executed one")
	}
}

// Among results of the same standing, confidence decides.
func TestBetterStoredFindingUsesConfidenceWithinSameStanding(t *testing.T) {
	low := &model.Finding{Confidence: 0.60}
	high := &model.Finding{Confidence: 0.80}
	if !betterStoredFinding(high, low) {
		t.Error("a higher-confidence result did not replace a lower-confidence one")
	}
	if betterStoredFinding(low, high) {
		t.Error("a lower-confidence result replaced a higher-confidence one")
	}

	lowVerified := &model.Finding{Confidence: 0.95, ExecutionVerified: true}
	highVerified := &model.Finding{Confidence: 0.99, ExecutionVerified: true}
	if !betterStoredFinding(highVerified, lowVerified) {
		t.Error("confidence was ignored among equally-verified results")
	}
	if betterStoredFinding(lowVerified, highVerified) {
		t.Error("a weaker execution replaced a stronger one")
	}
}
