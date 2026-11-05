package dom

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wqnmlgb151/XSSscan/pkg/browser"
	"github.com/wqnmlgb151/XSSscan/pkg/model"
	"github.com/wqnmlgb151/XSSscan/pkg/ssrfguard"
)

// A sink hit must be attributable to the page code that reached it. The stack is read
// when the hook fires, so the innermost page frame is the expression that actually ran
// — evidence a static script offset cannot give, because an offset identifies a region
// of a file rather than the call that executed.
func TestDOMBrowserCallSiteAttribution(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	if _, err := browser.FindChrome(); err != nil {
		t.Fatal(err)
	}

	// The page defines a named function that reaches the sink, so the captured frame
	// can be checked for a specific, non-incidental name rather than just "something".
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="host"></div><script>
function reachSink(value) {
    document.getElementById('host').innerHTML = value;
}
reachSink(decodeURIComponent(location.hash.slice(1)));
</script></body></html>`)
	}))
	defer server.Close()

	scanner, err := NewScanner(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	marker := "xsscanCallSiteMarker"
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	test := domXSSTest{Name: "fragment", Source: "location.hash", NavURL: buildURLWithFragment(u, marker)}
	findings, err := scanner.runSingleDOMTest(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL}, test, marker, marker)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a sink-flow candidate for the instrumented page")
	}
	evidence := findings[0].Evidence.Interaction
	if !strings.Contains(evidence, "called from") {
		t.Fatalf("no call site in evidence: %q", evidence)
	}
	// The captured frames must name the page's own code. Instrumentation frames are
	// filtered in the hook, so one appearing here means the filter is broken.
	if !strings.Contains(evidence, ":") {
		t.Fatalf("call site has no file:line: %q", evidence)
	}
	for _, internal := range []string{"callerFrames", "hooks.js", "record("} {
		if strings.Contains(evidence, internal) {
			t.Errorf("evidence names an instrumentation frame (%s): %q", internal, evidence)
		}
	}
}

// A hit in a page with no script of its own still has to report honestly: an unknown
// location must appear as unknown, not be dropped and read as "located elsewhere".
func TestDOMBrowserCallSiteUnknownIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	if _, err := browser.FindChrome(); err != nil {
		t.Fatal(err)
	}

	// The marker reaches the sink from an inline handler, where the stack may be thin.
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="host"></div><script>
document.getElementById('host').innerHTML = decodeURIComponent(location.hash.slice(1));
</script></body></html>`)
	}))
	defer server.Close()

	scanner, err := NewScanner(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	marker := "xsscanNoScriptMarker"
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	test := domXSSTest{Name: "fragment", Source: "location.hash", NavURL: buildURLWithFragment(u, marker)}
	findings, err := scanner.runSingleDOMTest(ssrfguard.WithPolicy(context.Background(), ssrfguard.Policy{AllowPrivate: true}), model.Target{URL: server.URL}, test, marker, marker)
	if err != nil {
		t.Fatalf("run reported: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a sink-flow candidate")
	}
	evidence := findings[0].Evidence.Interaction
	if !strings.Contains(evidence, "called from") && !strings.Contains(evidence, "call site not captured") {
		t.Fatalf("call-site state neither reported nor absent-stated: %q", evidence)
	}
}
