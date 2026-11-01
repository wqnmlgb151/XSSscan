package scanner

import (
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

// simulateDedup mimics the deduplication logic in Engine.Run()
func simulateDedup(findings []*model.Finding) []*model.Finding {
	seen := make(map[string]*model.Finding)
	for _, f := range findings {
		key := f.URL + "|" + f.Parameter + "|" + strings.Join(f.Contexts, ",")
		if existing, ok := seen[key]; ok {
			if f.Confidence > existing.Confidence {
				seen[key] = f
			}
		} else {
			seen[key] = f
		}
	}
	result := make([]*model.Finding, 0, len(seen))
	for _, f := range seen {
		result = append(result, f)
	}
	return result
}

func TestDedup_SameKeyKeepsHigherConfidence(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.70, Contexts: []string{"html_body"}},
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.85, Contexts: []string{"html_body"}},
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.60, Contexts: []string{"html_body"}},
	}

	result := simulateDedup(findings)
	if len(result) != 1 {
		t.Fatalf("Expected 1 deduplicated finding, got %d", len(result))
	}
	if result[0].Confidence != 0.85 {
		t.Errorf("Expected highest confidence 0.85, got %.2f", result[0].Confidence)
	}
}

func TestDedup_DifferentContextsAreSeparate(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.80, Contexts: []string{"html_body"}},
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.80, Contexts: []string{"js_string"}},
	}

	result := simulateDedup(findings)
	if len(result) != 2 {
		t.Errorf("Expected 2 findings (different contexts), got %d", len(result))
	}
}

func TestDedup_DifferentParamsAreSeparate(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.80, Contexts: []string{"html_body"}},
		{URL: "http://example.com/q", Parameter: "name", Confidence: 0.80, Contexts: []string{"html_body"}},
	}

	result := simulateDedup(findings)
	if len(result) != 2 {
		t.Errorf("Expected 2 findings (different params), got %d", len(result))
	}
}

func TestDedup_DifferentURLsAreSeparate(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/page1", Parameter: "q", Confidence: 0.80, Contexts: []string{"html_body"}},
		{URL: "http://example.com/page2", Parameter: "q", Confidence: 0.80, Contexts: []string{"html_body"}},
	}

	result := simulateDedup(findings)
	if len(result) != 2 {
		t.Errorf("Expected 2 findings (different URLs), got %d", len(result))
	}
}

func TestDedup_EmptyContexts(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.80, Contexts: nil},
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.90, Contexts: nil},
	}

	result := simulateDedup(findings)
	if len(result) != 1 {
		t.Fatalf("Expected 1 deduplicated finding, got %d", len(result))
	}
	if result[0].Confidence != 0.90 {
		t.Errorf("Expected highest confidence 0.90, got %.2f", result[0].Confidence)
	}
}

func TestDedup_MultipleContextsPreserved(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.80, Contexts: []string{"html_body", "js_string"}},
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.70, Contexts: []string{"html_body", "js_string"}},
	}

	result := simulateDedup(findings)
	if len(result) != 1 {
		t.Fatalf("Expected 1 deduplicated finding, got %d", len(result))
	}
	if result[0].Confidence != 0.80 {
		t.Errorf("Expected highest confidence 0.80, got %.2f", result[0].Confidence)
	}
}

func TestDedup_EmptyFindings(t *testing.T) {
	result := simulateDedup([]*model.Finding{})
	if len(result) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result))
	}
}

func TestDedup_SingleFinding(t *testing.T) {
	findings := []*model.Finding{
		{URL: "http://example.com/q", Parameter: "q", Confidence: 0.80, Contexts: []string{"html_body"}},
	}

	result := simulateDedup(findings)
	if len(result) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(result))
	}
}
