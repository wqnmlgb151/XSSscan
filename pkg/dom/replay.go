package dom

import (
	"fmt"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

/*
DOM candidate provenance (ENGINEERING_PLAN.md §25.7).

A DOM candidate cannot be verified the way a reflected one is. A reflected candidate is
reproduced by putting its payload into a query parameter and re-requesting; a DOM
candidate is reproduced by restoring *how the input reached the page* — which source,
through what channel, with what pre-existing storage, and after which interaction. The
plan states this directly: DOM verification must carry the source input method, the
initial storage state, the frame and the interaction steps, and must not squeeze every
DOM candidate into a query parameter for the reflection verifier.

This file records that provenance on the finding. It is deliberately descriptive rather
than executable: the fields say what a replay would have to reproduce, and an unknown
field is reported as unknown rather than defaulted, because a replay built on an assumed
input channel would be evidence about a different request than the one that fired.
*/

// replaySource identifies the channel a DOM input arrived through.
type replaySource string

const (
	replaySourceFragment    replaySource = "location.fragment"
	replaySourceQuery       replaySource = "location.search"
	replaySourcePath        replaySource = "location.pathname"
	replaySourceWindowName  replaySource = "window.name"
	replaySourceReferrer    replaySource = "document.referrer"
	replaySourceJSHref      replaySource = "javascript: url"
	replaySourceLocalStore  replaySource = "localStorage"
	replaySourceSessStore   replaySource = "sessionStorage"
	replaySourceCookie      replaySource = "document.cookie"
	replaySourcePostMessage replaySource = "window.postMessage"
	replaySourceUnknown     replaySource = "unknown"
)

// replayDescriptor is everything a replay needs that the navigation URL alone does not
// express. It is attached to the candidate so a verifier — and a human reviewer — can
// see which input produced it.
type replayDescriptor struct {
	// Source is the channel the input arrived through.
	Source replaySource
	// InputName is the parameter, key or property the value was written to, when the
	// channel has one. Empty for channels that carry no name (fragment, pathname).
	InputName string
	// Seed describes state that had to exist before the page loaded, such as a storage
	// entry or a cookie. Empty means none was needed.
	Seed string
	// Interaction describes an action required after load, such as dispatching a
	// message or triggering an event. Empty means the source is consumed on load.
	Interaction string
	// Frame names the browsing context the input targets. "top" for the main frame.
	Frame string
	// Unknown records provenance this scan could not establish. A non-empty value means
	// the replay cannot be built from these fields alone, which is a fact about the
	// evidence rather than a detail to be filled in by guessing.
	Unknown string
}

// describe renders the descriptor for reports, stating missing provenance explicitly.
func (d replayDescriptor) describe() string {
	parts := []string{"source=" + string(d.Source)}
	if d.InputName != "" {
		parts = append(parts, "input="+d.InputName)
	}
	if d.Frame != "" {
		parts = append(parts, "frame="+d.Frame)
	}
	if d.Seed != "" {
		parts = append(parts, "pre-existing state: "+d.Seed)
	} else {
		parts = append(parts, "no pre-existing state")
	}
	if d.Interaction != "" {
		parts = append(parts, "interaction: "+d.Interaction)
	} else {
		parts = append(parts, "no interaction step")
	}
	if d.Unknown != "" {
		parts = append(parts, "UNKNOWN: "+d.Unknown)
	}
	return "replay: " + strings.Join(parts, "; ")
}

// replayDescriptorFor derives a candidate's provenance from the test that produced it.
//
// Each base source writes its input through a different mechanism, so the descriptor is
// built per source rather than inferred from the payload. When a source's mechanism is
// not one this table knows, the descriptor says so instead of defaulting to the most
// common channel — a wrong channel would produce a replay that exercises a different
// input than the one that fired.
func replayDescriptorFor(test domXSSTest, marker string) replayDescriptor {
	d := replayDescriptor{Frame: "top"}
	switch test.Name {
	case "fragment":
		d.Source = replaySourceFragment
	case "search":
		d.Source = replaySourceQuery
	case "pathname":
		d.Source = replaySourcePath
	case "window.name":
		d.Source = replaySourceWindowName
		d.Seed = "window.name set before page scripts run"
	case "referrer":
		d.Source = replaySourceReferrer
		d.Seed = "document.referrer overridden before page scripts run"
	case "javascript-href":
		d.Source = replaySourceJSHref
		d.Interaction = "the crafted link must be navigated to"
	case "localStorage":
		d.Source = replaySourceLocalStore
		d.InputName = marker
		d.Seed = "localStorage entry keyed by the marker, written before page scripts run"
	case "sessionStorage":
		d.Source = replaySourceSessStore
		d.InputName = marker
		d.Seed = "sessionStorage entry keyed by the marker, written before page scripts run"
	case "document-cookie":
		d.Source = replaySourceCookie
		d.InputName = marker
		d.Seed = "cookie set on the target host with path=/ before page scripts run"
	case "postMessage":
		d.Source = replaySourcePostMessage
		d.Interaction = "window.postMessage after load, once the listener is registered"
	case "baseline":
		d.Source = replaySourceUnknown
		d.Unknown = "baseline pass carries no injected input"
	default:
		// Named query key probes: "search:<key>".
		if key, ok := strings.CutPrefix(test.Name, "search:"); ok {
			d.Source = replaySourceQuery
			d.InputName = key
			return d
		}
		if strings.HasPrefix(test.Name, "flow:") {
			// Data-flow-derived probes name their own source in test.Source.
			d.Source = replaySourceUnknown
			d.Unknown = "data-flow-derived input; channel recorded in the source description only"
			return d
		}
		d.Source = replaySourceUnknown
		d.Unknown = fmt.Sprintf("input channel for test %q is not described", test.Name)
	}
	return d
}

// domReplayCaveat states what a DOM candidate's evidence does and does not support.
//
// The plan requires that a proof obtained for an instrumented candidate is not
// transferred unconditionally to the original value. The instrumented run inserts a
// marker alongside the payload, so what fired is the marker-bearing variant, not the
// bare payload a user would deliver.
func domReplayCaveat(test domXSSTest) string {
	return "DOM caveat: this candidate was observed with the scanner's marker in the " +
		"input; execution of the unmarked original is not established by this observation"
}

// attachReplayProvenance writes the candidate's provenance onto its evidence so the
// report states how the input arrived, not merely that a sink was reached.
func attachReplayProvenance(finding *model.Finding, test domXSSTest, marker string) {
	descriptor := replayDescriptorFor(test, marker)
	finding.Evidence.Interaction = strings.Join([]string{
		finding.Evidence.Interaction,
		descriptor.describe(),
		domReplayCaveat(test),
	}, "; ")
}
