package verify

import (
	"testing"

	xctx "github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/payload"
)

func TestAssessmentPreservesNegativeReasons(t *testing.T) {
	p := payload.Payload{Value: `<script>alert(1)</script>`, Context: xctx.ContextHTMLBody}
	for _, tc := range []struct {
		name, body, contentType   string
		threshold                 float64
		code                      AssessmentCode
		exact, checked, candidate bool
	}{
		{"non_markup", p.Value, "application/json", .6, AssessmentNonMarkup, false, false, false},
		{"absent", "<body>safe</body>", "text/html", .6, AssessmentNotReflected, false, true, false},
		{"inert", "<textarea>" + p.Value + "</textarea>", "text/html", .6, AssessmentContextUnconfirmed, true, true, false},
		{"threshold", p.Value, "text/html", 1, AssessmentBelowThreshold, true, true, false},
		{"candidate", p.Value, "text/html", .6, AssessmentCandidate, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewVerifier().VerifyWithThreshold(tc.body, tc.body, p, model.InjectionPoint{}, nil, WAFResult{}, tc.threshold, tc.contentType)
			if r.Code != tc.code || r.Facts.ExactReflection != tc.exact || r.Facts.ReflectionChecked != tc.checked || r.Vulnerable != tc.candidate {
				t.Fatalf("unexpected assessment: %+v", r)
			}
			if r.Vulnerable && (!r.Facts.ContextConfirmed || r.Facts.ActualContext == xctx.ContextUnknown) {
				t.Fatal("candidate lost actual context")
			}
		})
	}
}
