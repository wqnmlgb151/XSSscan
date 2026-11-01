package dom

import (
	"strings"
	"testing"
)

// Every base source must describe how its input arrives. A DOM candidate is reproduced
// by restoring the input channel, so a descriptor that names the wrong channel would
// build a replay that exercises a different input than the one that fired.
func TestReplayDescriptorCoversEveryBaseSource(t *testing.T) {
	cases := []struct {
		testName  string
		wantSrc   replaySource
		wantName  string
		wantSeed  bool
		wantInter bool
	}{
		{"fragment", replaySourceFragment, "", false, false},
		{"search", replaySourceQuery, "", false, false},
		{"pathname", replaySourcePath, "", false, false},
		{"window.name", replaySourceWindowName, "", true, false},
		{"referrer", replaySourceReferrer, "", true, false},
		{"javascript-href", replaySourceJSHref, "", false, true},
		{"localStorage", replaySourceLocalStore, "xsscanMarker", true, false},
		{"sessionStorage", replaySourceSessStore, "xsscanMarker", true, false},
		{"document-cookie", replaySourceCookie, "xsscanMarker", true, false},
		{"postMessage", replaySourcePostMessage, "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.testName, func(t *testing.T) {
			d := replayDescriptorFor(domXSSTest{Name: tc.testName}, "xsscanMarker")
			if d.Source != tc.wantSrc {
				t.Errorf("source = %q, want %q", d.Source, tc.wantSrc)
			}
			if d.InputName != tc.wantName {
				t.Errorf("input name = %q, want %q", d.InputName, tc.wantName)
			}
			if (d.Seed != "") != tc.wantSeed {
				t.Errorf("seed presence = %v, want %v (%q)", d.Seed != "", tc.wantSeed, d.Seed)
			}
			if (d.Interaction != "") != tc.wantInter {
				t.Errorf("interaction presence = %v, want %v (%q)", d.Interaction != "", tc.wantInter, d.Interaction)
			}
			if d.Unknown != "" {
				t.Errorf("known source reported as unknown: %q", d.Unknown)
			}
			if d.Frame == "" {
				t.Error("frame not recorded")
			}
		})
	}
}

// A per-key query probe must name the key, not just the channel: two probes differ only
// by which parameter carries the input.
func TestReplayDescriptorNamesQueryKey(t *testing.T) {
	d := replayDescriptorFor(domXSSTest{Name: "search:redirect"}, "m")
	if d.Source != replaySourceQuery || d.InputName != "redirect" {
		t.Fatalf("query key probe not described: %+v", d)
	}
	if d.Unknown != "" {
		t.Fatalf("query key probe reported as unknown: %q", d.Unknown)
	}
}

// An input channel the table does not know must be reported as unknown. Defaulting to
// the most common channel would make the replay look reproducible while exercising a
// different input.
func TestReplayDescriptorReportsUnknownChannel(t *testing.T) {
	d := replayDescriptorFor(domXSSTest{Name: "some-new-source"}, "m")
	if d.Unknown == "" {
		t.Fatal("unknown input channel was silently given a source")
	}
	if d.Source != replaySourceUnknown {
		t.Fatalf("unknown channel reported as %q", d.Source)
	}
	if !strings.Contains(d.describe(), "UNKNOWN") {
		t.Fatalf("description hides the unknown provenance: %q", d.describe())
	}
}

// A data-flow-derived probe must not borrow the query channel: its input was chosen by
// static analysis and may arrive another way entirely.
func TestReplayDescriptorDataFlowProbeIsUnknown(t *testing.T) {
	d := replayDescriptorFor(domXSSTest{Name: "flow:localStorage:token"}, "m")
	if d.Source != replaySourceUnknown || d.Unknown == "" {
		t.Fatalf("data-flow probe claimed a concrete channel: %+v", d)
	}
}

// The description must state absent provenance rather than omitting it, so "no seed was
// needed" can be told apart from "the seed was not recorded".
func TestReplayDescriptorStatesAbsences(t *testing.T) {
	d := replayDescriptorFor(domXSSTest{Name: "fragment"}, "m")
	got := d.describe()
	if !strings.Contains(got, "no pre-existing state") {
		t.Errorf("absent seed not stated: %q", got)
	}
	if !strings.Contains(got, "no interaction step") {
		t.Errorf("absent interaction not stated: %q", got)
	}
}

// A DOM observation is made with the scanner's marker in the input, so it is not
// evidence that the unmarked original executes. The plan requires that this not be
// transferred unconditionally, so the caveat must travel with the candidate.
func TestDOMCandidateCarriesMarkerCaveat(t *testing.T) {
	caveat := domReplayCaveat(domXSSTest{Name: "fragment"})
	if !strings.Contains(caveat, "marker") || !strings.Contains(caveat, "not established") {
		t.Fatalf("caveat does not state the limitation: %q", caveat)
	}
}

// Provenance must actually reach the finding's evidence, not merely exist as a function.
func TestAttachReplayProvenanceReachesEvidence(t *testing.T) {
	finding := newDOMFinding(domXSSTest{Name: "localStorage", Source: "localStorage.getItem"}, "payload",
		"param", "desc", "fix", 0.65, nil)
	finding.Evidence.Interaction = "marker at offset 0 of 12 bytes"
	attachReplayProvenance(&finding, domXSSTest{Name: "localStorage"}, "xsscanMarker")

	got := finding.Evidence.Interaction
	for _, want := range []string{
		"marker at offset 0",          // the pre-existing detail is preserved
		"replay: source=localStorage", // the channel is named
		"pre-existing state:",         // the seed is described
		"DOM caveat:",                 // the limitation travels with it
	} {
		if !strings.Contains(got, want) {
			t.Errorf("evidence is missing %q: %q", want, got)
		}
	}
}
