package verify

import "github.com/wqnmlgb151/XSSscan/pkg/context"

// AssessmentCode describes the rule that ended verification, independently of
// confidence and of browser execution. An unconfirmed context is not proof of safety.
type AssessmentCode string

const (
	AssessmentUnknown            AssessmentCode = "unknown"
	AssessmentNonMarkup          AssessmentCode = "non_markup"
	AssessmentEmptyPayload       AssessmentCode = "empty_payload"
	AssessmentNotReflected       AssessmentCode = "not_reflected"
	AssessmentContextIneligible  AssessmentCode = "context_ineligible"
	AssessmentContextUnconfirmed AssessmentCode = "context_unconfirmed"
	AssessmentBelowThreshold     AssessmentCode = "below_threshold"
	AssessmentCandidate          AssessmentCode = "structural_candidate"
)

// AssessmentFacts reuses checks already performed by VerifyWithThreshold.
// False means no supporting evidence from that check, not a negative proof.
// ReflectionChecked distinguishes a completed search from an early return.
type AssessmentFacts struct {
	ReflectionChecked    bool
	ExactReflection      bool
	PartialReflection    bool
	ActualContext        context.ContextType
	ContextConfirmed     bool
	SyntaxValid          bool
	SanitizationDetected bool
	LengthLimited        bool
	// Transform names the specific change the server applied, when one was
	// established. It lets a caller react to *which* transformation happened
	// instead of only to the fact that something changed: the useful bypass
	// candidate differs between entity encoding, tag stripping and handler
	// removal, and a candidate that cannot address the observed change costs a
	// request while proving nothing.
	Transform TransformKind
}
