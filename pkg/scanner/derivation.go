package scanner

import (
	"os"
	"strconv"

	"github.com/xsscan/xsscan/pkg/payload"
	"github.com/xsscan/xsscan/pkg/verify"
)

/*
Feedback-driven candidate derivation (ENGINEERING_PLAN.md §25.6).

The previous behaviour asked a single question — "did this payload produce a
finding?" — and, when the answer was no, unconditionally tried up to five
mutations. That conflates two very different outcomes:

  - the payload never reached the response at all (no reflection, a different
    page, a transport problem), and
  - the payload reached the response but the server changed it (entity-encoded,
    truncated, wrapped in quotes).

Only the second is evidence that a filter exists and is worth circumventing. The
first is absence of evidence, and mutating a payload cannot create a reflection
that was never there: a WAF-bypass variant still has to be echoed back to be
observable. Sending five variants on every non-reflecting candidate is therefore
pure cost, which is what this gate removes.

The gate is deliberately conservative in the other direction too. It never
concludes that a parameter is safe, it only decides whether spending requests on
a derivation is justified by what was actually observed. When no signal justifies
a derivation, the candidate is reported as tested with no bypass attempted, and
the reason is recorded rather than left implicit.
*/

// derivationKind names the family of bypass a piece of evidence justifies.
type derivationKind string

const (
	// derivationNone means nothing observed justifies spending requests on a
	// bypass attempt.
	derivationNone derivationKind = ""
	// derivationStructural targets a server that alters or wraps the payload in
	// the response: entity encoding, case folding, quote wrapping, truncation.
	derivationStructural derivationKind = "structural"
	// derivationEncoding targets a server that refuses the request outright. The
	// payload never produced a response to analyse, so the only hypothesis left is
	// that a transport-layer inspector rejected it before the application saw it.
	derivationEncoding derivationKind = "encoding"
)

// derivationDecision is the outcome of the gate: how many bypass candidates the
// observed evidence justifies, which family they most likely belong to, and the
// reason behind that budget.
//
// The budget is the whole point. The previous behaviour had one fixed answer — five
// candidates, every time, regardless of what the attempt observed — which spent
// requests on bypasses for candidates that were never reflected. The plan asks for
// the opposite ("有明确过滤/阻断证据且变异能检验新的假设时才优先派生；没有信息时进入受限回退"),
// which is a graded budget rather than a switch.
//
// The family is advisory and drives diagnostics and ordering; it deliberately does
// NOT filter the candidate list. `payload.MutateTargeted` already narrows mutations
// to the strategies that work against a named WAF, and intersecting that with a
// second hand-maintained table silently dropped valid candidates — a Cloudflare
// case-mix bypass disappeared because the encoding-family list did not contain it.
// One source of truth for "which mutations suit this WAF" is worth more than a
// second opinion that can disagree with it.
type derivationDecision struct {
	// Budget is how many derivation candidates may be sent. Zero means none.
	Budget int
	Kind   derivationKind
	Reason string
}

// mayDerive reports whether this decision allows sending derivation candidates.
func (d derivationDecision) mayDerive() bool { return d.Budget > 0 }

// Derivation budgets. `derivationBudgetEvidence` matches the previous fixed bound of
// five, so a candidate with real evidence to act on is treated exactly as before;
// only the unevidenced path changes.
const (
	// derivationBudgetNone is used when the attempt produced nothing to reason
	// about at all.
	derivationBudgetNone = 0
	// derivationBudgetFallback is the bounded exploration allowed when the attempt
	// observed no filter. It keeps the bypass path alive at a fraction of its
	// previous cost instead of disabling it, so a server whose filtering is
	// invisible to reflection is still probed.
	derivationBudgetFallback = 1
	// derivationBudgetKnownTransform is used when the response was altered in a way
	// this scan can name. A named transformation is a much smaller hypothesis space
	// than "something changed", so fewer candidates can test it.
	//
	// This deliberately does NOT claim which mutation reverses which
	// transformation. The plan forbids reverse-solving an encoding order that was
	// never observed, and a hand-written "entity encoding → use hex entities" table
	// would be exactly that kind of unsupported guess. The size of the hypothesis
	// space is the defensible part.
	derivationBudgetKnownTransform = 2
	// derivationBudgetEvidence is used when a filter is evident but its form is not
	// established: a refusal, or an alteration this scan could not classify.
	derivationBudgetEvidence = 5
)

// transformBudget narrows the derivation budget when the observed transformation can
// be named. An unclassified transformation keeps the full budget, because nothing has
// been ruled out.
func transformBudget(transform verify.TransformKind) int {
	if transform == verify.TransformNone {
		return derivationBudgetEvidence
	}
	return derivationBudgetKnownTransform
}

// structuralDerivationTypes and encodingDerivationTypes describe which family a
// piece of evidence points at. They are used for diagnostics, not for filtering
// candidates: payload.MutateTargeted owns the WAF-to-strategy mapping.
func structuralDerivationTypes() map[payload.MutationType]bool {
	return map[payload.MutationType]bool{
		payload.MutationEntityAngleBrackets: true,
		payload.MutationCaseMix:             true,
		payload.MutationEntityPlusCase:      true,
		payload.MutationSpaceToSlash:        true,
		payload.MutationTabInjection:        true,
		payload.MutationNewlineInjection:    true,
		payload.MutationBacktickFn:          true,
		payload.MutationBreakoutTextarea:    true,
		payload.MutationCommentInjection:    true,
		payload.MutationAltFunction:         true,
		payload.MutationStringConcat:        true,
	}
}

// encodingDerivationTypes are the mutations that add an encoding layer. They are
// the natural hypothesis when the request itself did not come back, because they
// change what an inspector sees rather than what the application receives.
func encodingDerivationTypes() map[payload.MutationType]bool {
	return map[payload.MutationType]bool{
		payload.MutationDoubleURLEncode:   true,
		payload.MutationUnicodeFullwidth:  true,
		payload.MutationHTMLEntityNested:  true,
		payload.MutationUnicodeEscapeJS:   true,
		payload.MutationHexEntityMixed:    true,
		payload.MutationNullByteInjection: true,
	}
}

// derivationAllowed reports whether a mutation type belongs to the family the
// evidence points at. Used for diagnostics only — see structuralDerivationTypes.
func derivationAllowed(kind derivationKind, mt payload.MutationType) bool {
	switch kind {
	case derivationStructural:
		return structuralDerivationTypes()[mt]
	case derivationEncoding:
		return encodingDerivationTypes()[mt]
	default:
		return false
	}
}

// transformReason renders a named transformation for the decision's reason string,
// falling back to a neutral phrase when the change could not be classified.
func transformReason(transform verify.TransformKind) string {
	if transform == verify.TransformNone {
		return "unclassified alteration"
	}
	return string(transform)
}

// deriveAllowedFor is the wiring-level gate: it returns the decision for an attempt
// given whether its observation was retained.
//
// A missing observation must not fall back to a neighbouring attempt's facts. It can
// mean the sample was dropped by the retention bounds, and acting on evidence that
// belongs to a different attempt is exactly the kind of misattribution this scanner
// avoids elsewhere.
func deriveAllowedFor(observed attemptObservation, retained bool, waf verify.WAFResult) derivationDecision {
	if !retained {
		return derivationDecision{
			Kind:   derivationNone,
			Reason: "attempt evidence was not retained, so no filter behaviour was observed",
		}
	}
	return decideDerivation(observed, waf)
}

// decideDerivation maps what was observed for one candidate onto whether a bypass
// attempt is justified.
//
// Inputs are the facts the attempt already produced — no extra probing is done
// here, which is the point: the decision is free, only acting on it costs
// requests.
func decideDerivation(o attemptObservation, waf verify.WAFResult) derivationDecision {
	// A transport-level refusal is the one case where "nothing was reflected" is
	// itself evidence: the request did not get through, so an encoding layer is the
	// available hypothesis. This must be checked before the reflection states,
	// because a blocked request also has no reflection.
	if o.Failure != failureNone || waf.Detected {
		return derivationDecision{
			Budget: derivationBudgetEvidence,
			Kind:   derivationEncoding,
			Reason: "request refused or filtered before the response could be analysed",
		}
	}
	if o.Status >= 400 {
		return derivationDecision{
			Budget: derivationBudgetEvidence,
			Kind:   derivationEncoding,
			Reason: "server rejected the request with status " + strconv.Itoa(o.Status),
		}
	}
	// The analysis could not read the response, so nothing about filtering was
	// learned. Deriving here would be guessing, and even a bounded guess would be
	// based on a response that was never observed.
	if o.ResponseIncomplete || o.AnalysisLimited || o.Reflection == reflectionUnknown {
		return derivationDecision{
			Budget: derivationBudgetNone,
			Kind:   derivationNone,
			Reason: "response was not fully analysable, so no filter behaviour was observed",
		}
	}
	// The payload came back changed. That is direct evidence of a transforming
	// filter; the budget then depends on whether the change itself could be named.
	if o.Reflection == reflectionHTMLEncoded || o.Facts.SanitizationDetected {
		return derivationDecision{
			Budget: transformBudget(o.Facts.Transform),
			Kind:   derivationStructural,
			Reason: "payload was altered in the response (" + transformReason(o.Facts.Transform) + ")",
		}
	}
	if o.Facts.PartialReflection || o.Facts.LengthLimited {
		return derivationDecision{
			Budget: derivationBudgetEvidence,
			Kind:   derivationStructural,
			Reason: "payload was truncated in the response",
		}
	}
	// Nothing reflected. That is not evidence of a filter — mutating cannot make an
	// unreflected value appear — so the full budget is not justified. A single
	// bounded probe is kept because filtering can be invisible to reflection (a
	// server may drop the parameter entirely while still serving the page), and
	// dropping the bypass path altogether would trade coverage for request count,
	// which the plan forbids.
	if o.Reflection == reflectionNotObserved {
		return derivationDecision{
			Budget: derivationBudgetFallback,
			Kind:   derivationStructural,
			Reason: "payload was not reflected; bounded exploration only",
		}
	}
	// Reflected verbatim with no structural signal: the payload arrived intact, so
	// there is no filter to circumvent and no reason to spend a request re-sending a
	// variant of something the server already returned unchanged.
	return derivationDecision{
		Budget: derivationBudgetNone,
		Kind:   derivationNone,
		Reason: "payload was reflected unaltered; no filter behaviour to circumvent",
	}
}

// selectDerivations bounds how many derivation candidates one attempt may spawn.
//
// The hard cap is applied here rather than left to the caller, so no call site can
// reintroduce an unbounded derivation fan-out by passing a large limit.
//
// It does not filter by family — see derivationDecision. The gate that matters is the
// budget: an attempt with no observed reason to bypass still gets a bounded probe,
// but not the full range.
func selectDerivations(mutations []payload.Mutation, decision derivationDecision, limit int) []payload.Mutation {
	budget := min(decision.Budget, limit, maxDerivationsPerCandidate)
	if unconditionalDerivation {
		// Comparison mode: reproduce the pre-gate behaviour (always the full bound)
		// so a before/after measurement can be taken against the same binary.
		budget = min(limit, maxDerivationsPerCandidate)
	}
	if budget <= 0 {
		return nil
	}
	if len(mutations) > budget {
		return mutations[:budget]
	}
	return mutations
}

// unconditionalDerivation restores the previous "try mutations on every
// non-producing candidate" behaviour when the environment requests it.
//
// It exists so the gate can be measured against the behaviour it replaced without
// maintaining a second binary. It is not a user-facing option and defaults off.
var unconditionalDerivation = os.Getenv("XSCAN_UNCONDITIONAL_DERIVATION") == "1"

// describeDerivation renders the decision for diagnostics, so a reviewer can see why
// a given number of bypass candidates was or was not attempted.
func describeDerivation(d derivationDecision) string {
	if !d.mayDerive() {
		return "no bypass attempted: " + d.Reason
	}
	return "bypass attempted (" + string(d.Kind) + ", budget " + strconv.Itoa(d.Budget) + "): " + d.Reason
}
