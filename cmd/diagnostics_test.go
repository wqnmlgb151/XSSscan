package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

func TestCompactDiagnosticAndIssueGroups(t *testing.T) {
	message := "navigation blocked\nsource search failed\nsource pathname failed"
	compact := compactDiagnostic(message)
	if strings.Contains(compact, "\n") || !strings.Contains(compact, "navigation blocked") || !strings.Contains(compact, "2") {
		t.Fatalf("unbounded diagnostic: %q", compact)
	}
	issues := []model.ScanIssue{{Target: "local", Stage: "execution", Message: message}, {Target: "local", Stage: "execution", Message: message}, {Target: "local", Stage: "dom", Message: message}}
	groups := summarizeIssues(issues)
	if len(groups) != 2 || groups[0].Count != 2 || groups[1].Count != 1 || len(issues) != 3 {
		t.Fatalf("bad groups: %+v", groups)
	}
	if !rootCmd.SilenceErrors {
		t.Fatal("Cobra duplicates main's error output")
	}
}

func TestResultOutputGroupsErrorsAndLabelsUnverifiedFinding(t *testing.T) {
	defer saveCfg()()
	cfg.Verbose = false
	file, err := os.CreateTemp(t.TempDir(), "terminal-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	oldStdout, oldColor := os.Stdout, color.Output
	os.Stdout, color.Output = file, file
	defer func() { os.Stdout, color.Output = oldStdout, oldColor }()
	var issues []model.ScanIssue
	for i := 0; i < 40; i++ {
		issues = append(issues, model.ScanIssue{Target: "http://local", Stage: "execution", Message: "browser navigation failed"})
	}
	result := &model.ScanResult{Target: "http://local", Stats: model.ScanStats{Status: model.ScanPartial, Issues: issues}, Findings: []model.Finding{{Confidence: .9, Evidence: model.Evidence{VerificationError: "browser navigation failed"}}}}
	printResults(result, time.Second)
	content, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	out := string(content)
	if strings.Count(out, "  Issue:") != 1 || !strings.Contains(out, "repeated 40 times") || !strings.Contains(out, "Execution: INCOMPLETE") {
		t.Fatalf("misleading or repeated output: %s", out)
	}
	if len(result.Stats.Issues) != 40 {
		t.Fatal("console changed stored evidence")
	}
}
