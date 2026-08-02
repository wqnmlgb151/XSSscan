package dom

import (
	"net/url"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/analyze"
)

// --- jsStringLiteral ---

func TestJSStringLiteral_Basic(t *testing.T) {
	got := jsStringLiteral("hello")
	expected := `"hello"`
	if got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}

func TestJSStringLiteral_SingleQuote(t *testing.T) {
	// strconv.Quote wraps in double quotes, single quotes inside are NOT escaped
	// This is correct — single quotes inside a double-quoted string are safe
	got := jsStringLiteral("it's a test")
	expected := `"it's a test"`
	if got != expected {
		t.Errorf("Expected %s, got %s", expected, got)
	}
}

func TestJSStringLiteral_EmptyString(t *testing.T) {
	got := jsStringLiteral("")
	if got != `""` {
		t.Errorf("Expected empty quoted string, got %s", got)
	}
}

func TestJSStringLiteral_SpecialChars(t *testing.T) {
	got := jsStringLiteral(`hello"world`)
	// Double quotes inside must be escaped
	if !strings.Contains(got, `\"`) {
		t.Errorf("Expected escaped double quote, got %s", got)
	}
}

func TestJSStringLiteral_Newline(t *testing.T) {
	got := jsStringLiteral("line1\nline2")
	// Newline should be escaped
	if strings.Contains(got, "\n") {
		t.Errorf("Newline should be escaped, got %s", got)
	}
}

func TestJSStringLiteral_PayloadWithSingleQuote(t *testing.T) {
	// Critical: payload with single quote must not break out of JS string
	payload := `'; alert(1); //`
	got := jsStringLiteral(payload)
	// The result should be a valid JS string literal that, when evaluated,
	// produces the original payload
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("Expected double-quoted string, got %s", got)
	}
}

// --- buildSinkScript ---

func TestBuildSinkScript_ContainsMarker(t *testing.T) {
	marker := "xsscanABC123"
	script := buildSinkScript(marker)
	if !strings.Contains(script, marker) {
		t.Errorf("Sink script should contain marker %q", marker)
	}
}

func TestBuildSinkScript_ReplacesPlaceholder(t *testing.T) {
	script := buildSinkScript("testmarker")
	if strings.Contains(script, "{{MARKER}}") {
		t.Error("Sink script should not contain unreplaced {{MARKER}} placeholder")
	}
}

func TestBuildSinkScript_ContainsSinkChecks(t *testing.T) {
	script := buildSinkScript("any")
	// Should check for innerHTML sinks
	if !strings.Contains(script, "innerHTML") {
		t.Error("Sink script should check innerHTML")
	}
	// Should check for eval/Function sinks
	if !strings.Contains(script, "eval(") {
		t.Error("Sink script should check eval()")
	}
	// Should check for window.name transport
	if !strings.Contains(script, "window.name") {
		t.Error("Sink script should check window.name")
	}
}

func TestBuildSinkScript_DifferentMarkers(t *testing.T) {
	m1 := buildSinkScript("marker1")
	m2 := buildSinkScript("marker2")
	if m1 == m2 {
		t.Error("Different markers should produce different scripts")
	}
	if !strings.Contains(m1, "marker1") || !strings.Contains(m2, "marker2") {
		t.Error("Scripts should contain their respective markers")
	}
}

// --- buildDOMTests ---

func TestBuildDOMTests_FragmentTest(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	found := false
	for _, test := range tests {
		if test.Name == "fragment" {
			found = true
			if !strings.Contains(test.NavURL, "#") {
				t.Errorf("Fragment test URL should contain #: %s", test.NavURL)
			}
			break
		}
	}
	if !found {
		t.Error("Missing 'fragment' DOM test")
	}
}

func TestBuildDOMTests_WindowNameTest(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	found := false
	for _, test := range tests {
		if test.Name == "window.name" {
			found = true
			if test.Extra == "" {
				t.Error("window.name test should have Extra JS")
			}
			if !strings.Contains(test.Extra, "window.name") {
				t.Errorf("window.name Extra should set window.name, got: %s", test.Extra)
			}
			break
		}
	}
	if !found {
		t.Error("Missing 'window.name' DOM test")
	}
}

func TestBuildDOMTests_LocalStorageTest(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	found := false
	for _, test := range tests {
		if test.Name == "localStorage" {
			found = true
			if !strings.Contains(test.Extra, "localStorage.setItem") {
				t.Errorf("localStorage test Extra should call setItem, got: %s", test.Extra)
			}
			break
		}
	}
	if !found {
		t.Error("Missing 'localStorage' DOM test")
	}
}

func TestBuildDOMTests_PostMessageTest(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	found := false
	for _, test := range tests {
		if test.Name == "postMessage" {
			found = true
			if test.Extra == "" {
				t.Error("postMessage test should have Extra JS")
			}
			break
		}
	}
	if !found {
		t.Error("Missing 'postMessage' DOM test")
	}
}

func TestBuildDOMTests_UniqueNames(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	names := make(map[string]bool)
	for _, test := range tests {
		if names[test.Name] {
			t.Errorf("Duplicate test name: %s", test.Name)
		}
		names[test.Name] = true
	}
}

func TestBuildDOMTests_URLPreserved(t *testing.T) {
	u, _ := url.Parse("http://example.com/app/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	for _, test := range tests {
		if test.NavURL == "" {
			t.Errorf("Test %s has empty NavURL", test.Name)
			continue
		}
		// All URLs should reference the same host
		if !strings.Contains(test.NavURL, "example.com") {
			t.Errorf("Test %s NavURL lost host: %s", test.Name, test.NavURL)
		}
	}
}

// --- URL builder helpers ---

func TestBuildURLWithFragment(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	result := buildURLWithFragment(u, "test-fragment")
	if !strings.Contains(result, "#test-fragment") {
		t.Errorf("Expected fragment in URL, got %s", result)
	}
	// Original URL should be unchanged
	if u.Fragment != "" {
		t.Error("Original URL was mutated")
	}
}

func TestBuildURLWithQuery(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	result := buildURLWithQuery(u, "key", "value")
	if !strings.Contains(result, "key=value") {
		t.Errorf("Expected query param in URL, got %s", result)
	}
	// Original URL should be unchanged
	if len(u.Query()) != 0 {
		t.Error("Original URL was mutated")
	}
}

func TestBuildURLWithPathPrefix(t *testing.T) {
	u, _ := url.Parse("http://example.com/app")
	result := buildURLWithPathPrefix(u, "seg1/seg2")
	if !strings.Contains(result, "/app/seg1/seg2") {
		t.Errorf("Expected path prefix in URL, got %s", result)
	}
}

func TestBuildURLWithJavascriptHref(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	result := buildURLWithJavascriptHref(u, "marker", "alert(1)")
	// Should contain javascript: protocol encoded
	if !strings.Contains(result, "javascript") {
		t.Errorf("Expected javascript: in URL, got %s", result)
	}
}

// --- URL builder edge cases ---

func TestBuildURLWithFragment_EmptyFragment(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	result := buildURLWithFragment(u, "")
	// Empty fragment should produce URL without # suffix
	if strings.Contains(result, "#") {
		t.Errorf("Expected no fragment in URL, got %s", result)
	}
	// Original URL should be unchanged
	if u.Fragment != "" {
		t.Error("Original URL was mutated")
	}
}

func TestBuildURLWithQuery_ExistingQuery(t *testing.T) {
	u, _ := url.Parse("http://example.com/page?existing=param")
	result := buildURLWithQuery(u, "key", "value")
	// Both existing and new params should be present
	if !strings.Contains(result, "existing=param") {
		t.Errorf("Existing query param lost, got %s", result)
	}
	if !strings.Contains(result, "key=value") {
		t.Errorf("New query param missing, got %s", result)
	}
	// Original URL should be unchanged
	if u.Query().Get("key") != "" {
		t.Error("Original URL was mutated")
	}
}

func TestBuildURLWithPathPrefix_TrailingSlash(t *testing.T) {
	u, _ := url.Parse("http://example.com/app/")
	result := buildURLWithPathPrefix(u, "seg1/seg2")
	// Should not have double slash between path and prefix
	if strings.Contains(result, "//seg1") {
		t.Errorf("Double slash in path, got %s", result)
	}
	if !strings.Contains(result, "/app/seg1/seg2") {
		t.Errorf("Expected /app/seg1/seg2 in URL, got %s", result)
	}
}

func TestBuildURLWithPathPrefix_EmptyPath(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	result := buildURLWithPathPrefix(u, "seg1")
	// Should produce /seg1 even with empty original path
	if !strings.Contains(result, "/seg1") {
		t.Errorf("Expected /seg1 in URL, got %s", result)
	}
}

func TestBuildURLWithJavascriptHref_EncodesProperly(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	result := buildURLWithJavascriptHref(u, "marker", "alert(1)")
	// The colon in javascript: should be percent-encoded in the query value
	if strings.Contains(result, "javascript:alert") {
		t.Errorf("javascript: protocol should be URL-encoded, got %s", result)
	}
	// The word "javascript" should still appear (not encoded)
	if !strings.Contains(result, "javascript") {
		t.Errorf("Expected 'javascript' in URL, got %s", result)
	}
	// Should contain encoded colon %3A
	if !strings.Contains(result, "%3A") && !strings.Contains(result, "%3a") {
		t.Errorf("Expected encoded colon in URL, got %s", result)
	}
}

func TestBuildDOMTests_ExistingQueryPreserved(t *testing.T) {
	u, _ := url.Parse("http://example.com/page?existing=keep")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	for _, test := range tests {
		if !strings.Contains(test.NavURL, "existing=keep") {
			t.Errorf("Test %s lost existing query param: %s", test.Name, test.NavURL)
		}
	}
}

// --- Source completeness ---

func TestBuildDOMTests_All12SourcesPresent(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	expectedSources := []string{
		"fragment",
		"search",
		"pathname",
		"window.name",
		"referrer",
		"javascript-href",
		"inline-event",
		"localStorage",
		"sessionStorage",
		"document-cookie",
		"postMessage",
	}

	// Collect actual source names
	actualNames := make(map[string]bool)
	for _, test := range tests {
		actualNames[test.Name] = true
	}

	// Check all expected sources are present
	for _, expected := range expectedSources {
		if !actualNames[expected] {
			t.Errorf("Missing DOM test source: %s", expected)
		}
	}

	// Check total count matches
	if len(tests) != len(expectedSources) {
		t.Errorf("Expected %d DOM tests, got %d", len(expectedSources), len(tests))
	}
}

func TestBuildDOMTests_SourceDescriptionsNonEmpty(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	tests := buildDOMTests(u, "payload", analyze.MarkerPrefix)

	for _, test := range tests {
		if test.Source == "" {
			t.Errorf("Test %s has empty Source description", test.Name)
		}
	}
}
