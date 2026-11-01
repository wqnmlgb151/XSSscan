package model

import "testing"

func TestSummaryDoesNotInventCauses(t *testing.T) {
	for _, issue := range []ScanIssue{{Stage: "http", Message: "HTTP status 403"}, {Stage: "payload", Message: "ssrf blocked: private address"}} {
		if kind, ok := classifyIssue(issue); ok && (kind == ObservationAuthRequired || kind == ObservationWAFAnswered) {
			t.Fatalf("invented cause %s for %+v", kind, issue)
		}
	}
	if kind, _ := classifySkipReason("feature unavailable"); kind != ObservationModuleSkipped {
		t.Fatalf("invented skip cause: %s", kind)
	}
}
