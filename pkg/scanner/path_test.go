package scanner

import (
	"net/http"
	"testing"

	"github.com/wqnmlgb151/XSSscan/pkg/context"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

// mkInjection builds an injection point whose contexts carry explicit
// reflection anchors, mirroring what the detector now produces.
func mkInjection(target model.Target, param model.Parameter, ctxs ...context.Context) model.InjectionPoint {
	return model.InjectionPoint{Target: target, Parameter: param, Contexts: ctxs}
}

func anchored(t model.Target, param model.Parameter, c ...context.Context) (inputIdentity, string, []reflectionIdentity) {
	return reflectionIdentitiesFor(t, mkInjection(t, param, c...))
}

func ctxAt(ct context.ContextType, unit string, at int, tag, attr, quote string) context.Context {
	return context.Context{
		Type:           ct,
		ReflectionAt:   at,
		ReflectionUnit: unit,
		TagName:        tag,
		AttrName:       attr,
		QuoteChar:      quote,
	}
}

// Two positions in one response must be independent paths. This is the case the
// old whole-input fingerprint could not express, so it is the first thing the
// identity layer has to get right (ENGINEERING_PLAN.md §25.3).
func TestReflectionPositionsAreDistinct(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}

	// Same request, two reflections: one in the body, one inside a
	// single-quoted attribute.
	_, _, positions := anchored(target, param,
		ctxAt(context.ContextHTMLBody, "response_bytes", 10, "", "", ""),
		ctxAt(context.ContextHTMLAttrValue, "response_bytes", 40, "input", "value", "'"),
	)
	if len(positions) != 2 {
		t.Fatalf("expected two positions, got %d", len(positions))
	}
	if positions[0].id() == positions[1].id() {
		t.Fatalf("distinct reflection positions collapsed into one path: %q", positions[0].id())
	}
	for _, p := range positions {
		if !p.Anchored {
			t.Errorf("anchored context reported as unanchored: %+v", p)
		}
	}
}

// The identity must be reproducible: the same input yields the same path, or the
// scheduler cannot recognize equivalent work.
func TestReflectionIdentityIsStable(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	c := ctxAt(context.ContextJSString, "document_bytes", 7, "", "", "'")

	_, idA, posA := anchored(target, param, c)
	_, idB, posB := anchored(target, param, c)
	if idA != idB {
		t.Fatalf("input identity not stable: %q vs %q", idA, idB)
	}
	if posA[0].id() != posB[0].id() {
		t.Fatalf("position identity not stable: %q vs %q", posA[0].id(), posB[0].id())
	}
}

// Same parameter name in query and body must not share a path. The plan calls
// this out by name ("同名query/body必须不同") because the two requests can behave
// completely differently server-side.
func TestSameParamNameDifferentLocationIsDistinct(t *testing.T) {
	target := model.Target{
		URL:    "http://example.com/page?q=1",
		Method: http.MethodPost,
		Body:   "q=1",
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}
	c := ctxAt(context.ContextHTMLBody, "response_bytes", 5, "", "", "")

	_, queryID, _ := anchored(target, model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}, c)
	_, bodyID, _ := anchored(target, model.Parameter{Name: "q", Value: "1", Type: model.ParamBody}, c)
	if queryID == bodyID {
		t.Fatal("query and body parameters with the same name share one identity")
	}
}

// A different pre-existing value in an untouched parameter must produce a
// different path: the server may branch on it, so conclusions cannot be shared.
func TestDifferentVariantValueIsDistinct(t *testing.T) {
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	c := ctxAt(context.ContextHTMLBody, "response_bytes", 5, "", "", "")

	_, idA, _ := anchored(model.Target{URL: "http://example.com/page?q=1&lang=en"}, param, c)
	_, idB, _ := anchored(model.Target{URL: "http://example.com/page?q=1&lang=de"}, param, c)
	if idA == idB {
		t.Fatal("different non-injected parameter values share one identity")
	}
}

// A different authentication context is a different path, because the response
// may differ per identity or tenant.
func TestDifferentAuthIsDistinct(t *testing.T) {
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	c := ctxAt(context.ContextHTMLBody, "response_bytes", 5, "", "", "")

	anon := model.Target{URL: "http://example.com/page?q=1"}
	auth := model.Target{
		URL:     "http://example.com/page?q=1",
		Headers: map[string]string{"Authorization": "Bearer token-a"},
	}
	_, idA, _ := anchored(anon, param, c)
	_, idB, _ := anchored(auth, param, c)
	if idA == idB {
		t.Fatal("authenticated and anonymous requests share one identity")
	}

	// A different cookie value is a different identity too.
	other := model.Target{
		URL:     "http://example.com/page?q=1",
		Cookies: []*http.Cookie{{Name: "sid", Value: "b"}},
	}
	first := model.Target{
		URL:     "http://example.com/page?q=1",
		Cookies: []*http.Cookie{{Name: "sid", Value: "a"}},
	}
	_, idC, _ := anchored(first, param, c)
	_, idD, _ := anchored(other, param, c)
	if idC == idD {
		t.Fatal("different session cookies share one identity")
	}
}

// Different origins or methods are different paths.
func TestOriginAndMethodAreDistinct(t *testing.T) {
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	c := ctxAt(context.ContextHTMLBody, "response_bytes", 5, "", "", "")

	_, idA, _ := anchored(model.Target{URL: "http://example.com/p?q=1"}, param, c)
	_, idB, _ := anchored(model.Target{URL: "http://other.example.com/p?q=1"}, param, c)
	if idA == idB {
		t.Fatal("different origins share one identity")
	}

	_, idC, _ := anchored(model.Target{URL: "http://example.com/p?q=1", Method: http.MethodGet}, param, c)
	_, idD, _ := anchored(model.Target{URL: "http://example.com/p?q=1", Method: http.MethodPost}, param, c)
	if idC == idD {
		t.Fatal("different HTTP methods share one identity")
	}
}

// A context without an anchor must be flagged, not silently treated as a normal
// path: the plan forbids concluding that an unlocatable position is covered.
func TestUnanchoredContextIsFlagged(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}

	_, _, positions := anchored(target, param, context.Context{Type: context.ContextHTMLBody})
	if len(positions) != 1 {
		t.Fatalf("expected one position, got %d", len(positions))
	}
	if positions[0].Anchored {
		t.Fatal("context without an anchor was not flagged as unanchored")
	}
	if positions[0].id() == "" {
		t.Fatal("unanchored position produced an empty path id")
	}

	// An unanchored position must never be chosen as the primary path while an
	// anchored one exists.
	_, inputID, mixed := anchored(target, param,
		context.Context{Type: context.ContextHTMLBody},
		ctxAt(context.ContextHTMLBody, "response_bytes", 3, "", "", ""),
	)
	if primaryPathID(inputID, mixed) != mixed[1].id() {
		t.Fatal("primary position did not prefer the anchored context")
	}
}

// Two contexts that share a position key must still be separate ordinals, so a
// repeated reflection does not look like one single position.
func TestRepeatedPositionKeysGetDistinctOrdinals(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	same := ctxAt(context.ContextHTMLBody, "response_bytes", 9, "", "", "")

	_, _, positions := anchored(target, param, same, same)
	if len(positions) != 2 {
		t.Fatalf("expected two positions, got %d", len(positions))
	}
	if positions[0].id() == positions[1].id() {
		t.Fatal("repeated position keys produced one path")
	}
	if positions[0].Index != 0 || positions[1].Index != 1 {
		t.Fatalf("unexpected ordinals: %d, %d", positions[0].Index, positions[1].Index)
	}
}

// The injected parameter's own value must NOT participate in the identity:
// otherwise every candidate payload would form a new path and the scheduler
// could never recognise equivalent work.
func TestInjectedValueDoesNotChangeIdentity(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	c := ctxAt(context.ContextHTMLBody, "response_bytes", 5, "", "", "")

	_, idA, _ := anchored(target, model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}, c)
	_, idB, _ := anchored(target, model.Parameter{Name: "q", Value: "2", Type: model.ParamQuery}, c)
	if idA != idB {
		t.Fatal("the injected parameter's value leaked into the identity")
	}
}

// An unparsable URL must mark the identity incomplete rather than produce a
// confident path: an incomplete identity cannot license a scheduling decision.
func TestUnparsableURLMarksIdentityIncomplete(t *testing.T) {
	target := model.Target{URL: "http://[::1"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	input, id, _ := anchored(target, param, ctxAt(context.ContextHTMLBody, "response_bytes", 1, "", "", ""))
	if !input.Incomplete {
		t.Fatal("expected Incomplete for an unparsable URL")
	}
	if id == "" {
		t.Fatal("expected an identity-unavailable handle, got empty")
	}
}

// A JSON body's shape participates in the identity, but the injected value does
// not, so two bodies of the same shape share a path.
func TestBodyShapeIsPartOfIdentity(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamBody}
	c := ctxAt(context.ContextJSONValue, "response_bytes", 3, "", "", "\"")

	_, idA, _ := anchored(model.Target{URL: "http://example.com/api", Method: http.MethodPost, Body: `{"q":"1","keep":"x"}`, Headers: headers}, param, c)
	_, idB, _ := anchored(model.Target{URL: "http://example.com/api", Method: http.MethodPost, Body: `{"q":"2","keep":"x"}`, Headers: headers}, param, c)
	if idA != idB {
		t.Fatal("injected JSON value changed the identity")
	}

	_, idC, _ := anchored(model.Target{URL: "http://example.com/api", Method: http.MethodPost, Body: `{"other":"1"}`, Headers: headers}, param, c)
	if idA == idC {
		t.Fatal("different JSON body shapes share one identity")
	}
}

// The identity must not be built from query-stripping normalization: two
// different original query values are different paths.
func TestQueryIsNotStrippedFromIdentity(t *testing.T) {
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}
	c := ctxAt(context.ContextHTMLBody, "response_bytes", 5, "", "", "")

	_, idA, _ := anchored(model.Target{URL: "http://example.com/page?q=1&id=10"}, param, c)
	_, idB, _ := anchored(model.Target{URL: "http://example.com/page?q=1&id=99"}, param, c)
	if idA == idB {
		t.Fatal("identity ignored a non-injected query parameter's value")
	}
}

// The primary path for a payload must come from a real position when one exists,
// and must fall back to the request identity when the parameter has no contexts.
func TestPrimaryPathFallsBackToInputIdentity(t *testing.T) {
	target := model.Target{URL: "http://example.com/page?q=1"}
	param := model.Parameter{Name: "q", Value: "1", Type: model.ParamQuery}

	_, inputID, positions := anchored(target, param)
	if len(positions) != 0 {
		t.Fatalf("expected no positions, got %d", len(positions))
	}
	if got := primaryPathID(inputID, positions); string(got) != inputID {
		t.Fatalf("expected fallback to the input identity, got %q", got)
	}
}
