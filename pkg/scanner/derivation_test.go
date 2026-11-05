package scanner

import (
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/analyze"
	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"

	"github.com/wqnmlgb151/XSSscan/pkg/payload"
	"github.com/wqnmlgb151/XSSscan/pkg/verify"
)

// The gate must spend the full derivation budget only when the attempt actually
// observed something a bypass could act on. This is the request-saving half of
// feedback-driven derivation.
func TestDerivationBudgetFollowsObservedEvidence(t *testing.T) {
	cases := []struct {
		name string
		obs  attemptObservation
		waf  verify.WAFResult
		want int
		kind derivationKind
	}{
		{
			name: "payload altered in the response",
			obs:  attemptObservation{Reflection: reflectionHTMLEncoded, Status: 200},
			want: derivationBudgetEvidence,
			kind: derivationStructural,
		},
		{
			name: "verifier flagged sanitisation",
			obs: attemptObservation{
				Reflection: reflectionExact, Status: 200,
				Facts: verify.AssessmentFacts{SanitizationDetected: true},
			},
			want: derivationBudgetEvidence,
			kind: derivationStructural,
		},
		{
			name: "named transformation narrows the hypothesis space",
			obs: attemptObservation{
				Reflection: reflectionExact, Status: 200,
				Facts: verify.AssessmentFacts{
					SanitizationDetected: true,
					Transform:            verify.TransformAngleEncoded,
				},
			},
			want: derivationBudgetKnownTransform,
			kind: derivationStructural,
		},
		{
			name: "unrecognised transformation keeps the full budget",
			obs: attemptObservation{
				Reflection: reflectionExact, Status: 200,
				Facts: verify.AssessmentFacts{SanitizationDetected: true},
			},
			want: derivationBudgetEvidence,
			kind: derivationStructural,
		},
		{
			name: "payload truncated",
			obs: attemptObservation{
				Reflection: reflectionExact, Status: 200,
				Facts: verify.AssessmentFacts{LengthLimited: true},
			},
			want: derivationBudgetEvidence,
			kind: derivationStructural,
		},
		{
			name: "request refused by the transport",
			obs:  attemptObservation{Reflection: reflectionUnknown, Failure: failureTransport},
			want: derivationBudgetEvidence,
			kind: derivationEncoding,
		},
		{
			name: "WAF detected",
			obs:  attemptObservation{Reflection: reflectionNotObserved, Status: 200},
			waf:  verify.WAFResult{Detected: true, Name: "Cloudflare"},
			want: derivationBudgetEvidence,
			kind: derivationEncoding,
		},
		{
			name: "server rejected with an error status",
			obs:  attemptObservation{Reflection: reflectionNotObserved, Status: 403},
			want: derivationBudgetEvidence,
			kind: derivationEncoding,
		},
		{
			name: "not reflected: bounded exploration only",
			obs:  attemptObservation{Reflection: reflectionNotObserved, Status: 200},
			want: derivationBudgetFallback,
		},
		{
			name: "reflected verbatim: nothing to circumvent",
			obs:  attemptObservation{Reflection: reflectionExact, Status: 200},
			want: derivationBudgetNone,
		},
		{
			name: "response was not analysable",
			obs:  attemptObservation{Reflection: reflectionUnknown, ResponseIncomplete: true, Status: 200},
			want: derivationBudgetNone,
		},
		{
			name: "analysis limit reached",
			obs:  attemptObservation{Reflection: reflectionUnknown, AnalysisLimited: true, Status: 200},
			want: derivationBudgetNone,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDerivation(tc.obs, tc.waf)
			if got.Budget != tc.want {
				t.Fatalf("budget = %d, want %d (reason: %s)", got.Budget, tc.want, got.Reason)
			}
			if got.Reason == "" {
				t.Error("decision carries no reason; a reviewer could not tell why the budget was chosen")
			}
			if tc.kind != derivationNone && got.Kind != tc.kind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.kind)
			}
		})
	}
}

// A bounded fallback must stay bounded: the point of the gate is that an
// unevidenced candidate costs far less than an evidenced one.
func TestFallbackBudgetIsSmallerThanEvidenceBudget(t *testing.T) {
	if derivationBudgetFallback <= 0 {
		t.Fatal("fallback budget of zero would disable the bypass path entirely")
	}
	if derivationBudgetFallback >= derivationBudgetEvidence {
		t.Fatalf("fallback budget %d is not a reduction from %d", derivationBudgetFallback, derivationBudgetEvidence)
	}
}

// Naming the transformation must cost strictly fewer candidates than an unnamed one,
// otherwise classifying the change buys nothing.
func TestNamedTransformCostsFewerCandidates(t *testing.T) {
	if derivationBudgetKnownTransform >= derivationBudgetEvidence {
		t.Fatalf("named-transform budget %d is not a reduction from %d",
			derivationBudgetKnownTransform, derivationBudgetEvidence)
	}
	if derivationBudgetKnownTransform < 1 {
		t.Fatal("named-transform budget of zero would stop testing a transformation we actually identified")
	}
	// Every named transformation must land on the narrowed budget, and an unnamed one
	// must not.
	for _, kind := range []verify.TransformKind{
		verify.TransformAngleEncoded,
		verify.TransformFullEntity,
		verify.TransformNumericEntity,
		verify.TransformTagStripped,
		verify.TransformEventHandlerRemoved,
	} {
		if got := transformBudget(kind); got != derivationBudgetKnownTransform {
			t.Errorf("transform %q produced budget %d, want %d", kind, got, derivationBudgetKnownTransform)
		}
	}
	if got := transformBudget(verify.TransformNone); got != derivationBudgetEvidence {
		t.Errorf("unnamed transform produced budget %d, want %d", got, derivationBudgetEvidence)
	}
}

// selectDerivations must never exceed the decision's budget, and a zero budget must
// yield nothing rather than falling back to "unlimited".
func TestSelectDerivationsRespectsBudget(t *testing.T) {
	mutations := []payload.Mutation{
		{Type: payload.MutationCaseMix, Value: "a"},
		{Type: payload.MutationDoubleURLEncode, Value: "b"},
		{Type: payload.MutationTabInjection, Value: "c"},
		{Type: payload.MutationUnicodeFullwidth, Value: "d"},
		{Type: payload.MutationCommentInjection, Value: "e"},
		{Type: payload.MutationAltFunction, Value: "f"},
	}
	cases := []struct {
		budget int
		want   int
	}{
		{derivationBudgetNone, 0},
		{derivationBudgetFallback, 1},
		{derivationBudgetEvidence, 5},
		// An oversized budget is still clamped by the hard cap, so no caller can
		// reintroduce an unbounded derivation fan-out by passing a big number.
		{99, maxDerivationsPerCandidate},
	}
	for _, tc := range cases {
		got := selectDerivations(mutations, derivationDecision{Budget: tc.budget}, maxDerivationsPerCandidate)
		if len(got) != tc.want {
			t.Errorf("budget %d produced %d candidates, want %d", tc.budget, len(got), tc.want)
		}
	}
	// The cap holds even when the caller passes a larger limit.
	got := selectDerivations(mutations, derivationDecision{Budget: 99}, 99)
	if len(got) != maxDerivationsPerCandidate {
		t.Fatalf("hard cap not enforced: %d candidates", len(got))
	}
}

// A mutation list shorter than the budget must be returned whole, not padded.
func TestSelectDerivationsHandlesShortList(t *testing.T) {
	mutations := []payload.Mutation{{Type: payload.MutationCaseMix, Value: "only"}}
	got := selectDerivations(mutations, derivationDecision{Budget: derivationBudgetEvidence}, maxDerivationsPerCandidate)
	if len(got) != 1 {
		t.Fatalf("expected the single candidate to survive, got %d", len(got))
	}
}

// selectDerivations preserves the mutator's ordering, which is how WAF-targeted
// strategies stay prioritised.
func TestSelectDerivationsPreservesOrder(t *testing.T) {
	mutations := []payload.Mutation{
		{Type: payload.MutationCaseMix, Value: "first"},
		{Type: payload.MutationTabInjection, Value: "second"},
		{Type: payload.MutationAltFunction, Value: "third"},
	}
	got := selectDerivations(mutations, derivationDecision{Budget: 2}, maxDerivationsPerCandidate)
	if len(got) != 2 || got[0].Value != "first" || got[1].Value != "second" {
		t.Fatalf("order not preserved: %+v", got)
	}
}

// A missing observation must not silently borrow a neighbouring attempt's facts.
func TestDerivationWithoutRetainedEvidenceIsDisallowed(t *testing.T) {
	decision := deriveAllowedFor(attemptObservation{}, false, verify.WAFResult{})
	if decision.mayDerive() {
		t.Fatal("a decision was made without retained evidence")
	}
	if decision.Reason == "" {
		t.Fatal("missing-evidence decision carries no reason")
	}
	// With retained evidence the same observation is judged on its merits.
	if got := deriveAllowedFor(attemptObservation{Reflection: reflectionNotObserved, Status: 200}, true, verify.WAFResult{}); !got.mayDerive() {
		t.Fatal("retained evidence was ignored")
	}
}

// The description must say which case applied, so a report reader can distinguish
// "no filter to bypass" from "bypass not attempted".
func TestDescribeDerivationDistinguishesCases(t *testing.T) {
	none := describeDerivation(derivationDecision{Budget: derivationBudgetNone, Reason: "no evidence"})
	if none == "" || !containsAll(none, "no bypass attempted", "no evidence") {
		t.Fatalf("unexpected description: %q", none)
	}
	some := describeDerivation(derivationDecision{Budget: derivationBudgetFallback, Kind: derivationStructural, Reason: "not reflected"})
	if !containsAll(some, "bypass attempted", "structural", "not reflected") {
		t.Fatalf("unexpected description: %q", some)
	}
}

// profileCompatibleFallback / filterByProfile boundary: a profile that blocks angle
// brackets must remove tag payloads rather than restore them, because restoring them
// was how the pruning silently cancelled itself and spent the whole candidate budget
// on payloads the profile had just measured as unable to execute.
func TestPruneDoesNotRestoreBlockedPayloads(t *testing.T) {
	profile := &analyze.FilterProfile{EncodesAngleBrackets: true}
	payloads := []payload.Payload{
		{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody},
		{Value: `<img src=x onerror=alert(1)>`, Context: xctx.ContextHTMLBody},
	}
	got := prunePayloads(payloads, profile)
	if len(got) != 0 {
		t.Fatalf("tag payloads survived a profile that blocks angle brackets: %+v", got)
	}
}

// A payload that does not need the blocked capability must still be admitted, so a
// profile cannot empty a context when a viable candidate exists.
func TestPruneKeepsProfileCompatiblePayload(t *testing.T) {
	profile := &analyze.FilterProfile{EncodesAngleBrackets: true, EncodesDoubleQuote: true}
	payloads := []payload.Payload{
		{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody},
		{Value: `javascript:alert(1)`, Context: xctx.ContextURLAttr},
	}
	got := prunePayloads(payloads, profile)
	if len(got) != 1 || got[0].Value != `javascript:alert(1)` {
		t.Fatalf("expected only the angle-free payload to survive: %+v", got)
	}
}

// The widening safety net is the coverage guarantee: when a profile empties a
// context, the run must look for candidates that do not depend on the blocked
// capability instead of silently sending nothing.
func TestWidenForEmptiedContextsFindsCompatibleCandidates(t *testing.T) {
	profiles := analyze.ContextFilters{
		xctx.ContextHTMLBody: {EncodesAngleBrackets: true},
	}
	candidates := []payload.Payload{
		{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody},
		{Value: `"onmouseover=alert(1)`, Context: xctx.ContextHTMLAttrValue},
	}
	got := widenForEmptiedContexts(candidates, profiles)
	if len(got) != 1 || got[0].Value != `"onmouseover=alert(1)` {
		t.Fatalf("safety net did not admit the compatible candidate: %+v", got)
	}
}

// The safety net must not become a back door that restores exactly what the profile
// measured, or the reduction is back to zero.
func TestWidenForEmptiedContextsRespectsProfile(t *testing.T) {
	profiles := analyze.ContextFilters{
		xctx.ContextHTMLBody: {EncodesAngleBrackets: true},
	}
	candidates := []payload.Payload{
		{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody},
		{Value: `<svg onload=alert(1)>`, Context: xctx.ContextHTMLBody},
	}
	if got := widenForEmptiedContexts(candidates, profiles); len(got) != 0 {
		t.Fatalf("safety net restored payloads the profile rules out: %+v", got)
	}
}

// With no profile there is nothing to narrow against; every candidate is admitted.
func TestWidenForEmptiedContextsWithoutProfile(t *testing.T) {
	candidates := []payload.Payload{{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody}}
	if got := widenForEmptiedContexts(candidates, nil); got != nil {
		t.Fatalf("expected no widening without a profile, got %+v", got)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !contains(s, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
