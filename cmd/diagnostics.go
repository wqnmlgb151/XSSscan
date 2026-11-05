package main

import (
	"fmt"
	"strings"

	"github.com/wqnmlgb151/XSSscan/pkg/model"
)

// compactDiagnostic bounds terminal noise without changing report evidence.
func compactDiagnostic(message string) string {
	lines := strings.Split(strings.TrimSpace(stripANSI(message)), "\n")
	first := strings.TrimSpace(lines[0])
	runes := []rune(first)
	if len(runes) > 320 {
		first = string(runes[:320]) + "..."
	}
	if len(lines) > 1 {
		first += fmt.Sprintf(" (+%d diagnostic lines; --verbose or --output for details)", len(lines)-1)
	}
	return first
}

func terminalDiagnostic(message string) string {
	if cfg.Verbose {
		return stripANSI(message)
	}
	return compactDiagnostic(message)
}

type issueSummary struct {
	Issue model.ScanIssue
	Count int
}

func summarizeIssues(issues []model.ScanIssue) []issueSummary {
	type key struct{ target, stage, message string }
	positions := make(map[key]int)
	var groups []issueSummary
	for _, issue := range issues {
		k := key{issue.Target, issue.Stage, issue.Message}
		if index, ok := positions[k]; ok {
			groups[index].Count++
			continue
		}
		positions[k] = len(groups)
		groups = append(groups, issueSummary{Issue: issue, Count: 1})
	}
	return groups
}
