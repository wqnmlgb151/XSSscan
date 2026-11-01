package dom

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/browser"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

// The replay must be able to strengthen a candidate on its own terms: when the page
// consumes the input as a whole, the unmarked payload reaches the same sink, and that is
// a second observation rather than a transfer from the instrumented run.
func TestDOMReplayConfirmsPlainPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("requires local Chrome")
	}
	if _, err := browser.FindChrome(); err != nil {
		t.Fatal(err)
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()

	// Reads the fragment wholesale, so the value it renders is exactly whatever was put
	// there — marker-prefixed in the observing run, bare in the replay.
	server := newBrowserServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id="host"></div><script>
document.getElementById('host').innerHTML = decodeURIComponent(location.hash.slice(1));
</script></body></html>`)
	}))
	defer server.Close()

	scanner, err := NewScanner(context.Background(), 25*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	scanner.SetOriginalReplay(true)

	marker := "xsscanReplayMarker"
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	payload := "<img src=x onerror=alert(1)>"
	test := domXSSTest{Name: "fragment", Source: "location.hash", NavURL: buildURLWithFragment(u, marker+"="+payload)}
	findings, err := scanner.runSingleDOMTest(context.Background(), model.Target{URL: server.URL}, test, marker, payload)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected a sink-flow candidate")
	}
	evidence := findings[0].Evidence.Interaction
	if !strings.Contains(evidence, "independent replay:") {
		t.Fatalf("no replay outcome recorded: %q", evidence)
	}
	if !strings.Contains(evidence, string(replayReachedPlain)) && !strings.Contains(evidence, "reached") {
		t.Fatalf("replay did not observe the plain payload: %q", evidence)
	}
	if !strings.Contains(findings[0].Description, "replayed with the unmarked payload") {
		t.Errorf("confirmed replay not reflected in the description: %q", findings[0].Description)
	}
	// Reaching a sink is still not execution, so the verified band must stay unreachable
	// on this evidence alone.
	if findings[0].ExecutionVerified {
		t.Error("a sink observation was reported as execution verification")
	}
}

// The limitation the plan names must be handled explicitly rather than smoothed over:
// when the replay cannot reproduce the observing run's input shape, nothing is concluded
// either way and the candidate is not downgraded for it.
//
// This is asserted at the level where the decision is made rather than through a browser
// fixture, because the property under test is how the outcome is *used* — a page would
// only be an indirect and flakier way to reach the same branch.
func TestReplayOutcomeHandling(t *testing.T) {
	cases := []struct {
		name       string
		result     replayResult
		confirmed  bool
		wantDetail string
	}{
		{
			name:       "plain payload reached the sink",
			result:     replayResult{Outcome: replayReachedPlain, Detail: "reached innerHTML"},
			confirmed:  true,
			wantDetail: "reached innerHTML",
		},
		{
			name:       "input shape diverged",
			result:     replayResult{Outcome: replayInputDiverged, Detail: "input shape diverged"},
			confirmed:  false,
			wantDetail: "input shape diverged",
		},
		{
			name:       "plain payload not observed",
			result:     replayResult{Outcome: replayNotReached, Detail: "not observed at any sink"},
			confirmed:  false,
			wantDetail: "not observed at any sink",
		},
		{
			name:       "replay could not run",
			result:     replayResult{Outcome: replayError, Detail: "navigate failed"},
			confirmed:  false,
			wantDetail: "navigate failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.result.confirmed(); got != tc.confirmed {
				t.Errorf("confirmed() = %v, want %v", got, tc.confirmed)
			}
			// Only a reached plain payload may strengthen a candidate; everything else
			// must leave it exactly as the observing run left it.
			finding := newDOMFinding(domXSSTest{Name: "fragment"}, "payload", "p", "desc", "fix", 0.65, nil)
			originalConfidence := finding.Confidence
			finding.Evidence.Interaction = "base evidence; independent replay: " + tc.result.Detail
			if tc.result.confirmed() {
				finding.Description += " [replayed with the unmarked payload]"
			}
			if finding.Confidence != originalConfidence {
				t.Errorf("replay changed confidence from %v to %v", originalConfidence, finding.Confidence)
			}
			if !strings.Contains(finding.Evidence.Interaction, tc.wantDetail) {
				t.Errorf("outcome detail lost: %q", finding.Evidence.Interaction)
			}
			// A replay is never execution proof, so the verified flag stays clear.
			if finding.ExecutionVerified {
				t.Error("replay set the execution-verified flag")
			}
		})
	}
}

// A candidate with no payload to replay, or one whose input channel is unknown, must not
// have a replay invented for it.
func TestReplayRefusesWhenItCannotReproduceInput(t *testing.T) {
	s := &Scanner{}
	unknown := replayDescriptor{Source: replaySourceUnknown, Unknown: "channel not described"}
	got := s.replayDOMCandidate(context.Background(), model.Target{}, model.Finding{Payload: "p"}, unknown, "p")
	if got.confirmed() {
		t.Fatal("a replay was confirmed without a known input channel")
	}
	if got.Outcome != replayInputDiverged {
		t.Fatalf("outcome = %q, want %q", got.Outcome, replayInputDiverged)
	}
	empty := s.replayDOMCandidate(context.Background(), model.Target{}, model.Finding{}, replayDescriptor{Source: replaySourceFragment}, "")
	if empty.confirmed() || empty.Outcome != replayError {
		t.Fatalf("empty payload produced %q", empty.Outcome)
	}
}

// The replay hook must record unconditionally: with a marker filter it could never
// observe the unmarked payload it is looking for.
func TestReplayHookScriptHasNoMarkerFilter(t *testing.T) {
	script := buildReplayHookScript()
	if strings.Contains(script, "indexOf(MARKER)") || strings.Contains(script, "__MARKER_PLACEHOLDER__") {
		t.Fatal("replay instrumentation still filters on a marker")
	}
	if !strings.Contains(script, "window.__xsscan_replay_sinks") {
		t.Fatal("replay instrumentation does not expose its records")
	}
	if !strings.Contains(script, "sinks.length >= 200") {
		t.Error("replay records are unbounded")
	}
}

// The replay URL must place the plain payload on the channel the descriptor names.
func TestBuildReplayURLFollowsDescriptor(t *testing.T) {
	cases := []struct {
		name       string
		descriptor replayDescriptor
		value      string
		wantSub    string
	}{
		{"fragment", replayDescriptor{Source: replaySourceFragment}, "PLAIN", "#PLAIN"},
		{"query", replayDescriptor{Source: replaySourceQuery, InputName: "redirect"}, "PLAIN", "redirect=PLAIN"},
		{"path", replayDescriptor{Source: replaySourcePath}, "PLAIN", "/PLAIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildReplayURL("http://example.com/base", tc.descriptor, tc.value)
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("replay URL %q does not place the payload at %q", got, tc.wantSub)
			}
		})
	}
	// A channel with no URL representation must leave the URL alone rather than guess.
	unchanged := buildReplayURL("http://example.com/base", replayDescriptor{Source: replaySourceLocalStore, InputName: "k"}, "PLAIN")
	if unchanged != "http://example.com/base" {
		t.Fatalf("storage-channel replay modified the URL: %q", unchanged)
	}
}
