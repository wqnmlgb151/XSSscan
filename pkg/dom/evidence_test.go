package dom

import (
	"strings"
	"testing"
)

// A hit must report where the marker actually sat, so a reviewer never has to infer
// it from a snippet. The previous instrumentation stored a prefix of the value, which
// lost the marker entirely once it sat past the cut.
func TestSinkRecordCarriesMarkerPosition(t *testing.T) {
	hit := sinkResult{
		Sink: "innerHTML", Value: "…padded…xsscanMARKER…tail…",
		ValueLength: 5000, MarkerAt: 4200,
		WindowStart: 4120, WindowEnd: 4458, WindowTruncated: true,
	}
	coverage := hookCoverage{Reported: true, TotalInstalled: 3}
	got := describeSinkWindow(hit, coverage)
	for _, want := range []string{"offset 4200", "of 5000 bytes", "[4120,4458)", "partial", "3 hooks installed"} {
		if !strings.Contains(got, want) {
			t.Errorf("description %q is missing %q", got, want)
		}
	}
}

// A complete window must not be described as partial, or every capture would look
// suspicious and the flag would carry no information.
func TestSinkWindowCompleteIsNotFlaggedPartial(t *testing.T) {
	hit := sinkResult{Sink: "eval", Value: "xsscanMARKER", ValueLength: 13, MarkerAt: 0, WindowStart: 0, WindowEnd: 13}
	got := describeSinkWindow(hit, hookCoverage{Reported: true, TotalInstalled: 1})
	if strings.Contains(got, "partial") {
		t.Fatalf("complete window described as partial: %q", got)
	}
}

// Instrumentation completeness must be readable from the read-back state, including
// the blind spots. "window.__xsscan_hooks exists" does not prove every hook installed.
func TestHookCoverageReportsBlindSpots(t *testing.T) {
	evidence := hookEvidence{
		Installed: true,
		Status:    map[string]bool{"innerHTML": true, "eval": true, "location.href": false},
	}
	coverage := evidence.summarise()
	if !coverage.Reported {
		t.Fatal("coverage did not record that the instrumentation reported state")
	}
	if coverage.TotalInstalled != 2 {
		t.Fatalf("installed count = %d, want 2", coverage.TotalInstalled)
	}
	if len(coverage.Failed) != 1 || coverage.Failed[0] != "location.href" {
		t.Fatalf("blind spot not reported: %+v", coverage.Failed)
	}
	got := coverage.describe()
	if !strings.Contains(got, "location.href") {
		t.Fatalf("description omits the failed hook: %q", got)
	}
}

// An instrumentation set that reports no per-hook state must say so rather than
// implying a complete hook set.
func TestHookCoverageWithoutStatusIsReportedAsUnknown(t *testing.T) {
	coverage := hookEvidence{Installed: true}.summarise()
	if coverage.Reported {
		t.Fatal("expected reported=false when no per-hook state was supplied")
	}
	got := coverage.describe()
	if !strings.Contains(got, "not reported") {
		t.Fatalf("unknown coverage not described as such: %q", got)
	}
}

// Reaching the record cap is a truncated observation, not an absence of sinks, and
// must be surfaced.
func TestHookCoverageSurfacesOverflow(t *testing.T) {
	coverage := hookEvidence{
		Installed: true, Overflowed: true,
		Status: map[string]bool{"innerHTML": true},
	}.summarise()
	if !coverage.Overflowed {
		t.Fatal("overflow was dropped")
	}
	if got := coverage.describe(); !strings.Contains(got, "cap reached") {
		t.Fatalf("overflow not reported: %q", got)
	}
}

// A sink whose instrumentation alters page semantics must be labelled in the evidence,
// so its hit is not read as equivalent to one from a transparent wrapper.
func TestEvalSinkCarriesInstrumentationCaveat(t *testing.T) {
	hit := sinkResult{Sink: "eval", Value: "xsscanMARKER", ValueLength: 12, MarkerAt: 0, WindowStart: 0, WindowEnd: 12}
	got := describeSinkWindow(hit, hookCoverage{Reported: true, TotalInstalled: 1})
	if !strings.Contains(got, "direct-eval semantics") {
		t.Fatalf("eval hit is not labelled with its instrumentation caveat: %q", got)
	}
	// A transparent sink must not carry a caveat, or the label would mean nothing.
	transparent := sinkResult{Sink: "innerHTML", Value: "xsscanMARKER", ValueLength: 12, MarkerAt: 0, WindowStart: 0, WindowEnd: 12}
	if plain := describeSinkWindow(transparent, hookCoverage{Reported: true, TotalInstalled: 1}); strings.Contains(plain, "caveat") {
		t.Fatalf("transparent sink wrongly labelled: %q", plain)
	}
}

// The call site is the strongest locating evidence the instrumentation produces, so it
// must appear in the evidence when captured.
func TestCallSiteAppearsInEvidence(t *testing.T) {
	hit := sinkResult{
		Sink: "innerHTML", Value: "xsscanMARKER", ValueLength: 12, MarkerAt: 0, WindowStart: 0, WindowEnd: 12,
		Frames: []sinkFrame{
			{File: "http://target/app.js", Line: 42, Column: 7},
			{File: "http://target/app.js", Line: 11, Column: 3},
		},
	}
	got := describeSinkWindow(hit, hookCoverage{Reported: true, TotalInstalled: 1})
	if !strings.Contains(got, "called from http://target/app.js:42:7") {
		t.Fatalf("call site missing from evidence: %q", got)
	}
	if !strings.Contains(got, "app.js:11:3") {
		t.Fatalf("outer frames missing from evidence: %q", got)
	}
}

// A frame whose location could not be read must be reported as unknown rather than
// dropped, so a missing location is never mistaken for a located one.
func TestUnreadableFrameIsReportedAsUnknown(t *testing.T) {
	hit := sinkResult{
		Sink: "eval", Value: "xsscanMARKER", ValueLength: 12,
		Frames: []sinkFrame{{File: "unknown", Line: 0, Column: 0}},
	}
	got := describeSinkWindow(hit, hookCoverage{Reported: true, TotalInstalled: 1})
	if !strings.Contains(got, "unknown location") {
		t.Fatalf("unreadable frame silently dropped: %q", got)
	}
}

// No frames is a statement about the instrumentation, not about the sink.
func TestMissingCallSiteIsStatedNotImplied(t *testing.T) {
	hit := sinkResult{Sink: "innerHTML", Value: "xsscanMARKER", ValueLength: 12}
	got := describeSinkWindow(hit, hookCoverage{Reported: true, TotalInstalled: 1})
	if !strings.Contains(got, "call site not captured") {
		t.Fatalf("missing call site was not stated: %q", got)
	}
}

// The hooks.js source must expose the instrumentation state this Go code reads, and
// must keep matching on the full value before windowing around the marker.
func TestHooksSourceExposesInstrumentationState(t *testing.T) {
	source := hookScript
	if source == "" {
		t.Fatal("hooks.js was not embedded")
	}
	for _, want := range []string{
		"window.__xsscan_hook_status",
		"window.__xsscan_hooks_overflowed",
		"hookStatus[name] = true",
		"marker_at:",
		"window_truncated:",
		"value.indexOf(MARKER)",
		"frames: callerFrames()",
		"function callerFrames()",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("hooks.js is missing %q", want)
		}
	}
	// The stack is read only when a hit is recorded: an unfired hook has nothing to
	// locate, and a stack capture costs far more than the interception itself.
	if strings.Contains(source, "function record(sinkName, value) {\n        var raw") {
		t.Error("hooks.js appears to capture a stack before deciding whether there is a hit")
	}
	// A prefix capture is the bug this replaced: the window must be computed from the
	// marker's offset, not from the start of the value.
	if strings.Contains(source, "value.substring(0, 300)") {
		t.Error("hooks.js still captures a prefix of the value instead of a window around the marker")
	}
}
