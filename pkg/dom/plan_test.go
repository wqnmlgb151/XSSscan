package dom

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestFlowPlanExtendsWithoutDroppingOriginalMatrix(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/app?existing=seed")
	plan := &documentPlan{flows: []model.JSDataFlow{{Source: "query", Key: "view", Sink: "innerHTML"}, {Source: "query", Key: "existing", Sink: "eval"}, {Source: "localStorage", Key: "template", Sink: "innerHTML"}}}
	tests := buildPlannedDOMTests(u, "<img src=x onerror=alert(1)>", "xsscanPlanMarker", plan)
	if len(tests) != len(buildDOMTests(u, "p", "m"))+2 {
		t.Fatal(tests)
	}
	seen := map[string]int{}
	for _, test := range tests {
		seen[test.Name]++
		if test.Name == "search:view" {
			parsed, _ := url.Parse(test.NavURL)
			if parsed.Query().Get("view") != "xsscanPlanMarker=<img src=x onerror=alert(1)>" || parsed.Query().Get("existing") != "seed" || len(test.Flows) != 1 {
				t.Fatal(test)
			}
		}
	}
	for _, test := range buildDOMTests(u, "p", "m") {
		if seen[test.Name] != 1 {
			t.Fatalf("original source lost/duplicated: %s", test.Name)
		}
	}
	if seen["localStorage:template"] != 1 {
		t.Fatal(seen)
	}
}

func TestFlowPlanBoundsAdditionalKeys(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1/app")
	plan := &documentPlan{}
	for i := 0; i < 100; i++ {
		plan.flows = append(plan.flows, model.JSDataFlow{Source: "query", Key: fmt.Sprintf("key%d", i), Sink: "innerHTML"})
	}
	if got := len(buildPlannedDOMTests(u, "p", "xsscan123", plan)); got != 34 {
		t.Fatalf("unbounded additional matrix: %d", got)
	}
}

func TestPlanKeyIncludesAuthenticationAndBody(t *testing.T) {
	s := &Scanner{}
	target := model.Target{URL: "http://127.0.0.1/app", Method: "POST", Body: "view=one", Headers: map[string]string{"Authorization": "one"}, Cookies: []*http.Cookie{{Name: "session", Value: "one"}}}
	base, err := s.requestPlanKey(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model.Target){func(t *model.Target) { t.Body = "view=two" }, func(t *model.Target) { t.Headers = map[string]string{"Authorization": "two"} }, func(t *model.Target) { t.Cookies = []*http.Cookie{{Name: "session", Value: "two"}} }, func(t *model.Target) { t.Method = "GET" }} {
		modified := target
		change(&modified)
		key, err := s.requestPlanKey(modified)
		if err != nil || key == base {
			t.Fatal("plan crossed request/session boundary")
		}
	}
}
