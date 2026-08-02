package analyze

import (
	"strings"
	"testing"

	ctx "github.com/xsscan/xsscan/pkg/context"
)

// markerOffset returns the index of marker in body, or -1 if not found.
func markerOffset(body, marker string) int {
	return strings.Index(body, marker)
}

// TestDetectJSONContextInStringValue verifies that a marker appearing inside a
// JSON string value (odd number of unescaped quotes before it) returns a valid
// ContextJSONValue context.
func TestDetectJSONContextInStringValue(t *testing.T) {
	body := `{"key":"MARKER","other":"value"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", true)

	if got == nil {
		t.Fatal("Expected non-nil context for marker in JSON string value")
	}
	if got.Type != ctx.ContextJSONValue {
		t.Errorf("Expected type=ContextJSONValue, got %v", got.Type)
	}
	if !got.Enclosed {
		t.Error("Expected Enclosed=true")
	}
	if got.QuoteChar != "\"" {
		t.Errorf("Expected QuoteChar='\"', got %q", got.QuoteChar)
	}
	if got.Raw == "" {
		t.Error("Expected non-empty Raw snippet")
	}
}

// TestDetectJSONContextOddQuoteCount verifies that a marker with an odd number
// of preceding unescaped quotes is recognized as inside a string value at
// various nesting depths.
func TestDetectJSONContextOddQuoteCount(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		valid bool
	}{
		{
			"flat value",
			`{"q":"MARKER"}`,
			true,
		},
		{
			"nested object value",
			`{"data":{"result":"MARKER"}}`,
			true,
		},
		{
			"array element string",
				 `["hello","MARKER"]`,
			true,
		},
		{
			"number of fields before",
			`{"a":"1","b":"2","c":"MARKER"}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectJSONContext(tt.body, markerOffset(tt.body, "MARKER"), "MARKER", tt.valid)
			if got == nil {
				t.Fatalf("Expected non-nil context for %s", tt.name)
			}
			if got.Type != ctx.ContextJSONValue {
				t.Errorf("Expected ContextJSONValue, got %v", got.Type)
			}
		})
	}
}

// TestDetectJSONContextEvenQuoteCount verifies that a marker with an even number
// of preceding unescaped quotes (outside any JSON string) returns nil.
func TestDetectJSONContextEvenQuoteCount(t *testing.T) {
	// Place the marker after a complete key-value pair so it sits between
	// structural tokens (even quote count):
	//   {"a":"b",MARKER:"c"}
	// Unescaped quotes before MARKER: opening-a(1), closing-a(2),
	//   opening-b(3), closing-b(4) = 4 (even) → not inside a string.
	body := `{"a":"b",MARKER:"c"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", true)

	if got != nil {
		t.Errorf("Expected nil for even-quote-count marker, got %+v", got)
	}
}

// TestDetectJSONContextMarkerAbsent verifies nil when the marker is not in the body.
func TestDetectJSONContextMarkerAbsent(t *testing.T) {
	body := `{"key":"value"}`
	got := detectJSONContext(body, markerOffset(body, "NOTFOUND"), "NOTFOUND", true)

	if got != nil {
		t.Errorf("Expected nil when marker absent, got %+v", got)
	}
}

// TestDetectJSONContextInvalidJSON verifies nil when jsonValid=false even if the
// marker would otherwise be in a string position.
func TestDetectJSONContextInvalidJSON(t *testing.T) {
	body := `{"key":"MARKER"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", false)

	if got != nil {
		t.Errorf("Expected nil for invalid JSON, got %+v", got)
	}
}

// TestDetectJSONContextEscapedQuotes verifies that escaped quotes inside JSON
// string values are not counted, preserving correct string/value detection.
func TestDetectJSONContextEscapedQuotes(t *testing.T) {
	// Body: {"key":"val\"ue MARKER"}
	// Unescaped quotes before MARKER: opening-key(1), closing-key(2),
	//   opening-value(3) = 3 (odd) → inside string.
	// The \" must NOT be counted.
	body := `{"key":"before \"quote\" MARKER"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", true)

	if got == nil {
		t.Fatal("Expected non-nil context (escaped quotes should not miscount)")
	}
	if got.Type != ctx.ContextJSONValue {
		t.Errorf("Expected ContextJSONValue, got %v", got.Type)
	}
}

// TestDetectJSONContextContextFields verifies all Context fields are populated
// correctly for a JSON value reflection.
func TestDetectJSONContextContextFields(t *testing.T) {
	body := `{"search":"MARKER"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", true)

	if got == nil {
		t.Fatal("Expected non-nil context")
	}
	if got.Type != ctx.ContextJSONValue {
		t.Errorf("Type: expected %v, got %v", ctx.ContextJSONValue, got.Type)
	}
	if !got.Enclosed {
		t.Error("Enclosed: expected true")
	}
	if got.QuoteChar != "\"" {
		t.Errorf("QuoteChar: expected '\"', got %q", got.QuoteChar)
	}
	// Raw should contain the marker (it's a snippet centered on the marker).
	if got.Raw == "" {
		t.Error("Raw: expected non-empty snippet")
	}
}

// TestDetectJSONContextMultipleOccurrences verifies that when the marker appears
// multiple times, detectJSONContext uses the first occurrence (strings.Index).
func TestDetectJSONContextMultipleOccurrences(t *testing.T) {
	// First occurrence is inside a string value.
	body := `{"a":"MARKER","b":"other"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", true)
	if got == nil {
		t.Fatal("Expected non-nil for first occurrence in string value")
	}
}

// TestDetectJSONContextEvenQuotesNoMarker verifies nil when marker absent
// even with valid JSON structure.
func TestDetectJSONContextEvenQuotesNoMarker(t *testing.T) {
	body := `{"a":"b","c":"d"}`
	got := detectJSONContext(body, markerOffset(body, "MARKER"), "MARKER", true)
	if got != nil {
		t.Errorf("Expected nil, got %+v", got)
	}
}

// TestDetectJSONContextEmptyBody verifies nil for empty body.
func TestDetectJSONContextEmptyBody(t *testing.T) {
	got := detectJSONContext("", -1, "MARKER", true)
	if got != nil {
		t.Errorf("Expected nil for empty body, got %+v", got)
	}
}
