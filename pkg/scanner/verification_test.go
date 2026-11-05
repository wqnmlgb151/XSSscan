package scanner

import (
	"context"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/execverify"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"go.uber.org/zap"
)

func TestVerificationGroupStopsOnProofAndSkipsUnsupported(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	base := model.Finding{URL: "http://local/?q=x", Parameter: "q", ParamType: model.ParamQuery, Type: model.ReflectedXSS, Contexts: []string{"html_body"}, Confidence: 0.8}
	var input []model.Finding
	for _, p := range []string{`<script src=/missing.js></script>`, `<iframe srcdoc="<script>alert(1)</script>">`, `<script>alert(1)</script>`} {
		f := base
		f.Payload = p
		input = append(input, f)
	}
	groups := groupVerificationCandidates(input)
	count := 0
	got := e.verifyCandidateGroup(context.Background(), groups[0], model.Target{}, func(_ context.Context, f model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		count++
		if f.Payload != `<script>alert(1)</script>` {
			t.Fatalf("not simplest supported candidate: %s", f.Payload)
		}
		return &execverify.ExecutionResult{Executed: true, Confidence: 0.95, VerificationPayload: "exact-proof", DialogMessage: "exact-token"}, nil
	})
	if count != 1 || len(got) != 1 || !got[0].ExecutionVerified || got[0].Payload != `<script>alert(1)</script>` || len(got[0].Payloads) != 3 {
		t.Fatalf("invalid group proof/results: %d %+v", count, got)
	}
	if len(e.runIssues) != 0 {
		t.Fatalf("unneeded alternatives failed run: %+v", e.runIssues)
	}
}

func TestVerificationGroupTriesAlternativeAfterNegative(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	group := []model.Finding{{Payload: `<script>alert(1)</script>`, Confidence: .9}, {Payload: `<img src=x onerror=alert(1)>`, Confidence: .8}}
	count := 0
	got := e.verifyCandidateGroup(context.Background(), group, model.Target{}, func(_ context.Context, f model.Finding, _ model.Target) (*execverify.ExecutionResult, error) {
		count++
		return &execverify.ExecutionResult{Executed: count == 2, Confidence: .95, VerificationPayload: f.Payload}, nil
	})
	if count != 2 || len(got) != 1 || got[0].Payload != group[1].Payload || !got[0].ExecutionVerified {
		t.Fatalf("alternate proof lost: %+v", got)
	}
}

func TestVerificationGroupRetainsUnsupportedWithoutProof(t *testing.T) {
	e := NewEngine(Config{}, zap.NewNop(), nil)
	group := []model.Finding{{Parameter: "q", Payload: `<script>alert(1)</script>`}, {Parameter: "q", Payload: `<script>custom()</script>`}}
	got := e.verifyCandidateGroup(context.Background(), group, model.Target{}, func(context.Context, model.Finding, model.Target) (*execverify.ExecutionResult, error) {
		return &execverify.ExecutionResult{}, nil
	})
	if len(got) != 2 || got[1].Evidence.VerificationError == "" || len(e.runIssues) == 0 {
		t.Fatalf("unsupported negative group lost diagnostic: %+v %+v", got, e.runIssues)
	}
}

func TestVerificationGroupingSeparatesQueryAndBody(t *testing.T) {
	query := model.Finding{URL: "http://local/?q=x", Parameter: "q", ParamType: model.ParamQuery, Type: model.ReflectedXSS, Contexts: []string{"html_body"}, Payload: `<script>alert(1)</script>`}
	body := query
	body.ParamType = model.ParamBody
	if got := groupVerificationCandidates([]model.Finding{query, body}); len(got) != 2 {
		t.Fatalf("request channels merged: %+v", got)
	}
	if got := AggregateFindings([]model.Finding{query, body}); len(got) != 2 {
		t.Fatalf("report channels merged: %+v", got)
	}
	if got := SemanticDedup([]model.Finding{query, body}); len(got) != 2 {
		t.Fatalf("dedup channels merged: %+v", got)
	}
}

// Two reflection positions of the same parameter, in the same response, must be
// verified separately. The old key normalized the URL with NormalizeForDedup
// (which strips the query) and used the parameter name, so both positions landed in
// one group and a proof for one settled the other — the exact over-reach
// ENGINEERING_PLAN.md §25.15 warns about.
func TestVerificationGroupingSeparatesReflectionPositions(t *testing.T) {
	body := model.Finding{
		URL: "http://local/?q=x", Parameter: "q", ParamType: model.ParamQuery,
		Type: model.ReflectedXSS, Contexts: []string{"html_body"},
		Payload: `<script>alert(1)</script>`, ReflectionPath: "req1|response_bytes|html_body@10|q=\"",
	}
	attr := body
	attr.Contexts = []string{"html_attr_value"}
	attr.Payload = `"><script>alert(1)</script>`
	attr.ReflectionPath = "req1|response_bytes|html_attr_value@40|tag=input|attr=value|q='"

	groups := groupVerificationCandidates([]model.Finding{body, attr})
	if len(groups) != 2 {
		t.Fatalf("two reflection positions were merged into %d verification group(s)", len(groups))
	}
}

// The same parameter name reached through a different original query value is a
// different request identity, so a proof for one may not settle the other. The old
// key stripped the query and would have merged them.
func TestVerificationGroupingSeparatesVariantValues(t *testing.T) {
	base := model.Finding{
		URL: "http://local/?q=x&lang=en", Parameter: "q", ParamType: model.ParamQuery,
		Type: model.ReflectedXSS, Contexts: []string{"html_body"},
		Payload: `<script>alert(1)</script>`, ReflectionPath: "identity-en|response_bytes|html_body@10",
	}
	other := base
	other.URL = "http://local/?q=x&lang=de"
	other.ReflectionPath = "identity-de|response_bytes|html_body@10"

	if got := groupVerificationCandidates([]model.Finding{base, other}); len(got) != 2 {
		t.Fatalf("different original query values were merged into %d group(s)", len(got))
	}
}

// Candidates for the same position must still share a group, so verification keeps
// its early-stop behaviour instead of re-verifying every variant.
func TestVerificationGroupingKeepsSamePositionTogether(t *testing.T) {
	a := model.Finding{
		URL: "http://local/?q=x", Parameter: "q", ParamType: model.ParamQuery,
		Type: model.ReflectedXSS, Contexts: []string{"html_body"},
		Payload: `<script>alert(1)</script>`, ReflectionPath: "req1|response_bytes|html_body@10",
	}
	b := a
	b.Payload = `<img src=x onerror=alert(1)>`

	groups := groupVerificationCandidates([]model.Finding{a, b})
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("same-position candidates were split: %+v", groups)
	}
}

// A finding without a path must still be verified, not silently dropped. Falling
// back to the wider key verifies more than strictly needed, which is the safe
// direction; omitting it would leave the candidate unverified without saying so.
func TestVerificationGroupingHandlesMissingPath(t *testing.T) {
	anchored := model.Finding{
		URL: "http://local/?q=x", Parameter: "q", ParamType: model.ParamQuery,
		Type: model.ReflectedXSS, Contexts: []string{"html_body"},
		Payload: `<script>alert(1)</script>`, ReflectionPath: "req1|response_bytes|html_body@10",
	}
	unanchored := anchored
	unanchored.ReflectionPath = ""
	unanchored.Payload = `<svg onload=alert(1)>`

	groups := groupVerificationCandidates([]model.Finding{anchored, unanchored})
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	if total != 2 {
		t.Fatalf("a finding was dropped from verification: %d of 2 grouped", total)
	}
	// The unanchored finding must not be folded into the anchored position's group,
	// because nothing establishes that they cover the same position.
	if len(groups) != 2 {
		t.Fatalf("an unanchored finding was merged with an anchored one: %+v", groups)
	}
}

// An unanchored finding's identity may not depend on the reflection anchor, since
// there is none: two unanchored candidates for one parameter and context stay
// together rather than forming one group per payload.
func TestVerificationGroupingStableForUnanchoredFindings(t *testing.T) {
	a := model.Finding{
		URL: "http://local/?q=x", Parameter: "q", ParamType: model.ParamQuery,
		Type: model.ReflectedXSS, Contexts: []string{"html_body"},
		Payload: `<script>alert(1)</script>`,
	}
	b := a
	b.Payload = `<svg onload=alert(1)>`

	first := groupVerificationCandidates([]model.Finding{a, b})
	second := groupVerificationCandidates([]model.Finding{b, a})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("unanchored grouping is not stable: %d then %d groups", len(first), len(second))
	}
}
