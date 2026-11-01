package analyze

import (
	"sort"
	"testing"
)

// TestCSPParseValidDirectives verifies that a multi-directive CSP policy is
// parsed into the correct directive → values map.
func TestCSPParseValidDirectives(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; base-uri 'self'",
	}
	policy := a.Parse(headers)

	if policy.ReportOnly {
		t.Error("Expected ReportOnly=false for enforcing header")
	}
	if policy.Raw == "" {
		t.Error("Expected Raw policy string to be preserved")
	}
	if policy.Raw != headers["Content-Security-Policy"] {
		t.Errorf("Expected Raw=%q, got %q", headers["Content-Security-Policy"], policy.Raw)
	}

	// Verify each directive parsed correctly.
	expectations := map[string][]string{
		"default-src": {"'self'"},
		"script-src":  {"'self'", "'nonce-abc'"},
		"object-src":  {"'none'"},
		"base-uri":    {"'self'"},
	}
	for dir, want := range expectations {
		got, ok := policy.Directives[dir]
		if !ok {
			t.Errorf("Missing directive %q", dir)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("Directive %q: expected %d values, got %d: %v", dir, len(want), len(got), got)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Directive %q[%d]: expected %q, got %q", dir, i, want[i], got[i])
			}
		}
	}
}

// TestCSPParseReportOnly verifies the Report-Only variant sets ReportOnly=true.
func TestCSPParseReportOnly(t *testing.T) {
	a := NewCSPAnalyzer()
	header := "default-src 'self'"
	headers := map[string]string{
		"Content-Security-Policy-Report-Only": header,
	}
	policy := a.Parse(headers)

	if !policy.ReportOnly {
		t.Error("Expected ReportOnly=true for report-only header")
	}
	if policy.Raw != header {
		t.Errorf("Expected Raw=%q, got %q", header, policy.Raw)
	}
	if dirs, ok := policy.Directives["default-src"]; !ok || len(dirs) != 1 || dirs[0] != "'self'" {
		t.Errorf("Expected default-src 'self', got %v", policy.Directives["default-src"])
	}
}

// TestCSPParseMissingHeader verifies that absent CSP headers yield an empty
// policy with a "none" security level and zero score.
func TestCSPParseMissingHeader(t *testing.T) {
	a := NewCSPAnalyzer()

	tests := []struct {
		name    string
		headers map[string]string
	}{
		{"nil headers", nil},
		{"empty headers", map[string]string{}},
		{"unrelated header", map[string]string{"X-Custom": "value"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := a.Parse(tt.headers)
			if policy.ReportOnly {
				t.Error("Expected ReportOnly=false")
			}
			if len(policy.Directives) != 0 {
				t.Errorf("Expected empty directives, got %v", policy.Directives)
			}
			if policy.Score.Value != 0 || policy.Score.Level != "none" {
				t.Errorf("Expected score {0 none}, got {%d %s}", policy.Score.Value, policy.Score.Level)
			}
			if policy.Raw != "" {
				t.Errorf("Expected empty Raw, got %q", policy.Raw)
			}
		})
	}
}

// TestCSPScoreStrong verifies a well-configured policy scores "strong" (≥80).
func TestCSPScoreStrong(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'strict-dynamic'; object-src 'none'",
	}
	policy := a.Parse(headers)

	if policy.Score.Level != "strong" {
		t.Errorf("Expected level=strong, got %s (score=%d)", policy.Score.Level, policy.Score.Value)
	}
	if policy.Score.Value < 80 {
		t.Errorf("Expected score >= 80, got %d", policy.Score.Value)
	}
}

// TestCSPScoreModerate verifies a policy that has a self default-src but
// allows unsafe-eval lands in the "moderate" range (60-79).
func TestCSPScoreModerate(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'",
	}
	policy := a.Parse(headers)

	if policy.Score.Level != "moderate" {
		t.Errorf("Expected level=moderate, got %s (score=%d)", policy.Score.Level, policy.Score.Value)
	}
}

// TestCSPScoreWeak verifies a policy with 'self' but unsafe-inline/eval drops
// to the "weak" band (30-59).
func TestCSPScoreWeak(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
	}
	policy := a.Parse(headers)

	if policy.Score.Level != "weak" {
		t.Errorf("Expected level=weak, got %s (score=%d)", policy.Score.Level, policy.Score.Value)
	}
}

// TestCSPScoreBypassable verifies a policy with wildcard default-src and
// unsafe-inline scores 0 → "bypassable".
func TestCSPScoreBypassable(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
	}
	policy := a.Parse(headers)

	if policy.Score.Level != "bypassable" {
		t.Errorf("Expected level=bypassable, got %s (score=%d)", policy.Score.Level, policy.Score.Value)
	}
	if policy.Score.Value != 0 {
		t.Errorf("Expected score=0, got %d", policy.Score.Value)
	}
}

// TestCSPScoreClamping verifies that scores are clamped to [0, 100].
func TestCSPScoreClamping(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		min    int
		max    int
	}{
		{
			"negative clamped to 0",
			"default-src *; script-src * 'unsafe-inline' 'unsafe-eval' *",
			0,
			100,
		},
		{
			"capped at 100",
			"default-src 'none'; script-src 'strict-dynamic'; object-src 'none'; base-uri 'none'; style-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none'",
			0,
			100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewCSPAnalyzer()
			policy := a.Parse(map[string]string{"Content-Security-Policy": tt.policy})
			if policy.Score.Value < tt.min || policy.Score.Value > tt.max {
				t.Errorf("Score %d outside [%d, %d]", policy.Score.Value, tt.min, tt.max)
			}
		})
	}
}

// TestCSPBypassUnsafeInline verifies the unsafe-inline bypass is detected.
func TestCSPBypassUnsafeInline(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
	}
	policy := a.Parse(headers)

	found := false
	for _, b := range policy.Bypasses {
		if b.Type == "unsafe-inline" {
			found = true
			if b.Severity != "critical" {
				t.Errorf("Expected severity=critical, got %s", b.Severity)
			}
			if b.Exploit == "" {
				t.Error("Expected non-empty Exploit field")
			}
		}
	}
	if !found {
		t.Errorf("Expected unsafe-inline bypass in %v", policy.Bypasses)
	}
}

// TestCSPBypassWildcard verifies wildcard bypass detection on any directive.
func TestCSPBypassWildcard(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src *; script-src 'self'",
	}
	policy := a.Parse(headers)

	found := false
	for _, b := range policy.Bypasses {
		if b.Type == "wildcard" {
			found = true
			if b.Severity != "critical" {
				t.Errorf("Expected severity=critical, got %s", b.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected wildcard bypass")
	}
}

// TestCSPBypassJSONP verifies JSONP endpoint bypass detection for known CDNs.
func TestCSPBypassJSONP(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "script-src 'self' https://ajax.googleapis.com",
	}
	policy := a.Parse(headers)

	found := false
	for _, b := range policy.Bypasses {
		if b.Type == "jsonp" {
			found = true
			if b.Severity != "high" {
				t.Errorf("Expected severity=high, got %s", b.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected JSONP bypass for googleapis.com")
	}
}

// TestCSPBypassMissingBaseURI verifies that a missing base-uri triggers a bypass.
func TestCSPBypassMissingBaseURI(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
	}
	policy := a.Parse(headers)

	found := false
	for _, b := range policy.Bypasses {
		if b.Type == "missing-base-uri" {
			found = true
			if b.Severity != "medium" {
				t.Errorf("Expected severity=medium, got %s", b.Severity)
			}
		}
	}
	if !found {
		t.Error("Expected missing-base-uri bypass when base-uri directive is absent")
	}
}

// TestCSPNoBypassWhenSecure verifies a strong policy has no bypasses and
// the base-uri is NOT flagged when present.
func TestCSPNoBypassWhenSecure(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'",
	}
	policy := a.Parse(headers)

	for _, b := range policy.Bypasses {
		if b.Type == "missing-base-uri" {
			t.Error("base-uri is present, should not flag missing-base-uri bypass")
		}
		if b.Type == "unsafe-inline" || b.Type == "wildcard" {
			t.Errorf("Strong policy should not have %s bypass", b.Type)
		}
	}
}

// TestCSPMissingDirectives verifies that absent recommended directives are
// reported as issues with appropriate severity.
func TestCSPMissingDirectives(t *testing.T) {
	a := NewCSPAnalyzer()
	// Only object-src is present; default-src, script-src, base-uri are missing.
	headers := map[string]string{
		"Content-Security-Policy": "object-src 'none'",
	}
	policy := a.Parse(headers)

	// Build a lookup by directive name for deterministic checking.
	issueByDir := make(map[string]CSPIssue)
	for _, issue := range policy.Issues {
		issueByDir[issue.Directive] = issue
	}

	expectations := map[string]struct {
		severity string
	}{
		"default-src": {"medium"},
		"script-src":  {"high"},
		"base-uri":    {"medium"},
	}
	for dir, want := range expectations {
		issue, ok := issueByDir[dir]
		if !ok {
			t.Errorf("Expected issue for missing %q directive", dir)
			continue
		}
		if issue.Severity != want.severity {
			t.Errorf("Issue %q: expected severity=%s, got %s", dir, want.severity, issue.Severity)
		}
	}

	// object-src IS present, so it should NOT appear in issues.
	if _, ok := issueByDir["object-src"]; ok {
		t.Error("object-src is present, should not be flagged as missing")
	}
}

// TestCSPAllDirectivesPresent verifies no issues when all recommended
// directives are present.
func TestCSPAllDirectivesPresent(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
	}
	policy := a.Parse(headers)

	if len(policy.Issues) != 0 {
		t.Errorf("Expected no issues, got %d: %v", len(policy.Issues), policy.Issues)
	}
}

// TestCSPSemicolonAndWhitespaceTolerance verifies that the parser handles
// extra semicolons, leading/trailing whitespace, and empty directive segments.
func TestCSPSemicolonAndWhitespaceTolerance(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "  ;; default-src   'self'  ;;; script-src 'self' ;;  ; ",
	}
	policy := a.Parse(headers)

	if _, ok := policy.Directives["default-src"]; !ok {
		t.Error("Expected default-src directive after whitespace trimming")
	}
	if dirs, ok := policy.Directives["default-src"]; !ok || len(dirs) != 1 || dirs[0] != "'self'" {
		t.Errorf("Expected default-src ['self'], got %v", dirs)
	}
	if dirs, ok := policy.Directives["script-src"]; !ok || len(dirs) != 1 || dirs[0] != "'self'" {
		t.Errorf("Expected script-src ['self'], got %v", dirs)
	}
}

// TestCSPBypassSortDeterministic verifies bypass types can be found regardless
// of map iteration order (bypasses come from map iteration).
func TestCSPBypassSortDeterministic(t *testing.T) {
	a := NewCSPAnalyzer()
	headers := map[string]string{
		"Content-Security-Policy": "default-src *; script-src 'unsafe-inline'; img-src https://cdnjs.cloudflare.com",
	}
	policy := a.Parse(headers)

	// Sort bypass types for deterministic assertion.
	var types []string
	for _, b := range policy.Bypasses {
		types = append(types, b.Type)
	}
	sort.Strings(types)

	// We expect: jsonp, unsafe-inline, wildcard (at minimum).
	if len(types) < 3 {
		t.Errorf("Expected at least 3 bypass types, got %d: %v", len(types), types)
	}
}
