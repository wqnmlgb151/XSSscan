package model

import (
	"strings"
	"testing"
)

// The summary must have no way to express "not exploitable". If such a kind existed, a
// conclusion reached on one module's axis could be recorded here and reused on another —
// exactly what the plan forbids, since reflected XSS says nothing about stored output and
// a completed module says nothing about an untested one.
func TestSummaryHasNoNotExploitableConclusion(t *testing.T) {
	kinds := []ObservationKind{
		ObservationWAFAnswered, ObservationOriginUnreachable, ObservationAuthRequired,
		ObservationBrowserUnavailable, ObservationCallbackUnavailable,
		ObservationNoIndependentTrigger, ObservationFewParameters,
		ObservationModuleIncomplete, ObservationNoFindings,
	}
	for _, kind := range kinds {
		text := strings.ToLower(string(kind) + " " + ObservationDetail(kind))
		for _, forbidden := range []string{"not vulnerable", "safe", "not exploitable", "no vulnerability", "clean"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("kind %q reads as a conclusion (%q): %s", kind, forbidden, ObservationDetail(kind))
			}
		}
	}
}

// A module that completed without findings is recorded as an observation about the
// module, and the wording must say so rather than implying anything about the target.
func TestCompletedWithoutFindingsIsAboutTheModule(t *testing.T) {
	detail := ObservationDetail(ObservationNoFindings)
	if !strings.Contains(detail, "about the module") {
		t.Fatalf("wording does not attribute the observation to the module: %q", detail)
	}
	summary := BuildCrossModuleSummary([]ModuleResult{
		{Type: "reflected", Target: "http://t/", Status: ScanCompleted, Candidates: 20},
	}, nil, 1)
	observations := summary.Sorted()
	if len(observations) != 1 || observations[0].Kind != ObservationNoFindings {
		t.Fatalf("unexpected summary: %+v", observations)
	}
	if observations[0].Probeable {
		t.Error("a completed-without-findings observation was marked probeable")
	}
	if !strings.Contains(observations[0].Detail, "reflected") {
		t.Errorf("observation does not name the module: %q", observations[0].Detail)
	}
}

// An incomplete module's silence must be recorded as carrying no information, because a
// later reader would otherwise treat "no findings" and "did not run" as the same thing.
func TestIncompleteModuleSilenceCarriesNoInformation(t *testing.T) {
	for _, status := range []ScanStatus{ScanFailed, ScanCanceled, ScanPartial, ScanSkipped} {
		summary := BuildCrossModuleSummary([]ModuleResult{
			{Type: "dom", Target: "http://t/", Status: status, Reason: "unrecognised reason"},
		}, nil, 1)
		var found bool
		for _, observation := range summary.Sorted() {
			if observation.Kind == ObservationModuleIncomplete || observation.Kind == ObservationModuleSkipped {
				found = true
				if observation.Probeable {
					t.Errorf("status %s produced a probeable observation", status)
				}
			}
			if observation.Kind == ObservationNoFindings {
				t.Errorf("status %s was reported as completed without findings", status)
			}
		}
		if !found {
			t.Errorf("status %s produced no observation at all", status)
		}
	}
}

// A skipped module states its own reason; the observation must keep that text verbatim so
// the classification never replaces the evidence.
func TestSkipReasonIsPreservedVerbatim(t *testing.T) {
	reason := "callback endpoint not configured"
	summary := BuildCrossModuleSummary([]ModuleResult{
		{Type: "blind", Target: "http://t/", Status: ScanSkipped, Reason: reason},
	}, nil, 1)
	observations := summary.Sorted()
	if len(observations) != 1 {
		t.Fatalf("unexpected summary: %+v", observations)
	}
	if observations[0].Detail != reason {
		t.Errorf("reason was rewritten: %q", observations[0].Detail)
	}
	if observations[0].Kind != ObservationCallbackUnavailable {
		t.Errorf("kind = %q, want %q", observations[0].Kind, ObservationCallbackUnavailable)
	}
}

// An unrecognised skip reason must stay unclassified rather than be forced into a
// category that would claim more than the recorded text supports.
func TestUnrecognisedSkipReasonIsNotForcedIntoACategory(t *testing.T) {
	kind, probeable := classifySkipReason("something entirely new happened")
	if kind != ObservationModuleSkipped {
		t.Errorf("kind = %q; an unrecognised reason must fall back to the neutral kind", kind)
	}
	if probeable {
		t.Error("an unrecognised reason was marked probeable")
	}
}

// A WAF that answered is a probeable lead, and a bypass that was observed must be stated.
func TestWAFObservationRecordsBypass(t *testing.T) {
	summary := BuildCrossModuleSummary(nil, &WAFInfo{Name: "cloudflare", Bypassed: true}, 1)
	observations := summary.Sorted()
	if len(observations) != 1 || observations[0].Kind != ObservationWAFAnswered {
		t.Fatalf("unexpected summary: %+v", observations)
	}
	if !observations[0].Probeable {
		t.Error("a WAF observation was not marked probeable")
	}
	if !strings.Contains(observations[0].Detail, "bypass was observed") {
		t.Errorf("bypass not recorded: %q", observations[0].Detail)
	}
}

// Observations must be derived from recorded outcomes only: a module with no status, no
// issues and no counts contributes nothing.
func TestEmptyModuleProducesNothing(t *testing.T) {
	summary := BuildCrossModuleSummary([]ModuleResult{{Type: "reflected"}}, nil, 5)
	if len(summary.Observations) != 0 {
		t.Fatalf("an empty module produced observations: %+v", summary.Sorted())
	}
}

// Duplicates on (module, kind, subject) must collapse, so a module reporting the same
// issue repeatedly does not inflate the summary.
func TestSummaryDeduplicates(t *testing.T) {
	var summary CrossModuleSummary
	for i := 0; i < 5; i++ {
		summary.Add(CrossModuleObservation{Module: "stored", Kind: ObservationAuthRequired, Subject: "http://t/", Detail: "401"})
	}
	if len(summary.Observations) != 1 {
		t.Fatalf("duplicates were kept: %+v", summary.Observations)
	}
	// A different subject is a different observation.
	summary.Add(CrossModuleObservation{Module: "stored", Kind: ObservationAuthRequired, Subject: "http://u/", Detail: "401"})
	if len(summary.Observations) != 2 {
		t.Fatalf("a distinct subject was collapsed: %+v", summary.Observations)
	}
}

// A module consulting leads must not receive its own observations, and must receive only
// probeable ones — the summary hands over hints, not another module's verdicts.
func TestLeadsForModuleExcludesSelfAndNonProbeable(t *testing.T) {
	summary := BuildCrossModuleSummary([]ModuleResult{
		{Type: "reflected", Target: "http://t/", Status: ScanSkipped, Reason: "auth required"},
		{Type: "stored", Target: "http://t/", Status: ScanCompleted, Candidates: 5},
	}, &WAFInfo{Name: "cloudflare"}, 1)
	leads := summary.LeadsForModule("stored")
	for _, lead := range leads {
		if lead.Module == "stored" {
			t.Errorf("module received its own observation: %+v", lead)
		}
		if !lead.Probeable {
			t.Errorf("non-probeable observation was handed over as a lead: %+v", lead)
		}
	}
	if len(leads) == 0 {
		t.Fatal("no leads were produced although a probeable observation exists")
	}
}

// The rendered summary must be stable, so a report does not change between runs on the
// same recorded outcomes.
func TestSummaryRenderIsStable(t *testing.T) {
	modules := []ModuleResult{
		{Type: "stored", Target: "http://t/", Status: ScanCompleted, Candidates: 3},
		{Type: "blind", Target: "http://t/", Status: ScanSkipped, Reason: "callback endpoint not configured"},
		{Type: "reflected", Target: "http://t/", Status: ScanCompleted, Candidates: 10, Findings: 1},
	}
	first := BuildCrossModuleSummary(modules, &WAFInfo{Name: "cloudflare"}, 2).Describe()
	for i := 0; i < 20; i++ {
		if got := BuildCrossModuleSummary(modules, &WAFInfo{Name: "cloudflare"}, 2).Describe(); got != first {
			t.Fatalf("summary render is not stable:\n%s\n%s", first, got)
		}
	}
	if first == "" || strings.Contains(first, "no cross-module observations") {
		t.Fatalf("summary is empty: %q", first)
	}
}
