package scanner

import (
	"context"
	"errors"
	"github.com/xsscan/xsscan/test/testenv"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xsscan/xsscan/pkg/execverify"
	"github.com/xsscan/xsscan/pkg/model"
	"github.com/xsscan/xsscan/pkg/ssrfguard"
)

func TestVerificationErrorRetainsStructuralEvidence(t *testing.T) {
	engine := makeTestEngine()
	finding := model.Finding{Confidence: .9, Payload: "original", ExecutionVerified: true, ExecutionConfidence: .95}
	engine.applyVerificationError(&finding, &execverify.ExecutionResult{VerificationPayload: "probe", Interaction: "focus"}, errors.New("navigation blocked"))
	if finding.ExecutionVerified || finding.ExecutionConfidence != 0 || finding.Confidence != .9 || finding.Payload != "original" {
		t.Fatalf("invalid execution state: %+v", finding)
	}
	if finding.Evidence.VerificationError != "navigation blocked" || finding.Evidence.VerificationPayload != "probe" || finding.Evidence.Interaction != "focus" {
		t.Fatalf("error evidence lost: %+v", finding.Evidence)
	}
}

func TestVerifiedVariantClearsPrimaryVerificationError(t *testing.T) {
	findings := []model.Finding{
		{URL: "http://local/?q=a", Parameter: "q", Type: model.ReflectedXSS, Contexts: []string{"html_body"}, Payload: "failed-primary", Confidence: .9, Evidence: model.Evidence{VerificationError: "navigation failed"}},
		{URL: "http://local/?q=b", Parameter: "q", Type: model.ReflectedXSS, Contexts: []string{"html_body"}, Payload: "proven-variant", Confidence: .8, ExecutionVerified: true, ExecutionConfidence: .95, Evidence: model.Evidence{VerificationPayload: "proof", DialogMessage: "candidate-message"}},
	}
	got := AggregateFindings(findings)
	if len(got) != 1 || !got[0].ExecutionVerified || got[0].Evidence.VerificationError != "" || got[0].Evidence.DialogMessage != "candidate-message" || got[0].Payloads[0] != "proven-variant" {
		t.Fatalf("mixed proof: %+v", got)
	}
}

func TestVerificationNavigationFailureReportsCandidateError(t *testing.T) {
	if testing.Short() {
		t.Skip("local Chrome integration")
	}
	old := ssrfguard.AllowPrivate
	ssrfguard.AllowPrivate = true
	defer func() { ssrfguard.AllowPrivate = old }()
	var foreignHits atomic.Int64
	other := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits.Add(1) }))
	defer other.Close()
	seed := testenv.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer seed.Close()
	for _, count := range []int{1, 2} {
		engine := makeTestEngine()
		engine.config.VerifyTimeout = 15 * time.Second
		findings := make([]model.Finding, count)
		for i := range findings {
			findings[i] = model.Finding{URL: seed.URL + "?q=original", ParamType: model.ParamQuery, Parameter: "q", Payload: "<script>alert(1)</script>", Confidence: .9}
		}
		got := engine.verifyFindingsWithAuth(context.Background(), findings, nil, model.Target{URL: seed.URL + "?q=original"})
		for _, finding := range got {
			if finding.ExecutionVerified || finding.Confidence != .9 || !strings.Contains(finding.Evidence.VerificationError, "same-origin policy") || finding.Evidence.VerificationPayload == "" {
				t.Fatalf("missing failure proof: %+v", finding)
			}
		}
		if len(engine.runIssues) != 1 {
			t.Fatalf("repeated transport issues: %+v", engine.runIssues)
		}
	}
	if foreignHits.Load() != 0 {
		t.Fatal("foreign target contacted")
	}
}

func TestRunIssuesDeduplicateWhileRetainingErrorCount(t *testing.T) {
	engine := makeTestEngine()
	for i := 0; i < 8; i++ {
		engine.recordRunError("execution", errors.New("same failed navigation"))
	}
	if len(engine.runIssues) != 1 || atomic.LoadInt64(&engine.errors) != 8 {
		t.Fatalf("issue repetition: %+v errors=%d", engine.runIssues, atomic.LoadInt64(&engine.errors))
	}
	engine.recordRunError("dom", errors.New("same failed navigation"))
	if len(engine.runIssues) != 2 {
		t.Fatal("different stages were collapsed")
	}
}
