package request

import (
	"encoding/json"
	"mime/multipart"
	"strings"
	"testing"
)

func TestInjectBodyValueNestedKey(t *testing.T) {
	body := `{"user":{"name":"test","email":"test@example.com"}}`
	result := InjectBodyValue(body, "user.name", "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	user := data["user"].(map[string]interface{})
	if user["name"] != "MARKER" {
		t.Errorf("Expected user.name=MARKER, got %v", user["name"])
	}
	if user["email"] != "test@example.com" {
		t.Errorf("Expected email unchanged, got %v", user["email"])
	}
}

func TestInjectBodyValueArrayIndex(t *testing.T) {
	body := `{"items":[{"id":1,"name":"first"},{"id":2,"name":"second"}]}`
	result := InjectBodyValue(body, "items[0].name", "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	items := data["items"].([]interface{})
	first := items[0].(map[string]interface{})
	if first["name"] != "MARKER" {
		t.Errorf("Expected items[0].name=MARKER, got %v", first["name"])
	}
	second := items[1].(map[string]interface{})
	if second["name"] != "second" {
		t.Errorf("Expected items[1].name=second, got %v", second["name"])
	}
}

func TestInjectBodyValueNonExistentNestedKey(t *testing.T) {
	body := `{"user":{"name":"test"}}`
	result := InjectBodyValue(body, "user.address.city", "MARKER", map[string]string{"Content-Type": "application/json"})

	// With createMissing=true, non-existent nested keys are created.
	// This allows testing injection into APIs where the parameter doesn't exist yet.
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	user, ok := data["user"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected user object")
	}
	address, ok := user["address"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected address object created")
	}
	if address["city"] != "MARKER" {
		t.Errorf("Expected city=MARKER, got %v", address["city"])
	}
	// Original fields should be preserved
	if user["name"] != "test" {
		t.Errorf("Expected name preserved, got %v", user["name"])
	}
}

func TestInjectBodyValueTopLevelKey(t *testing.T) {
	body := `{"name":"test","email":"test@example.com"}`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	if data["name"] != "MARKER" {
		t.Errorf("Expected name=MARKER, got %v", data["name"])
	}
	if data["email"] != "test@example.com" {
		t.Errorf("Expected email unchanged, got %v", data["email"])
	}
}

func TestInjectBodyAllPreservesStructure(t *testing.T) {
	body := `{"user":{"name":"test","email":"test@example.com"},"active":true}`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	user := data["user"].(map[string]interface{})
	if user["name"] != "MARKER" {
		t.Errorf("Expected user.name=MARKER, got %v", user["name"])
	}
	if user["email"] != "MARKER" {
		t.Errorf("Expected user.email=MARKER, got %v", user["email"])
	}
	if data["active"] != "MARKER" {
		t.Errorf("Expected active=MARKER, got %v", data["active"])
	}
}

func TestInjectBodyAllDeeplyNested(t *testing.T) {
	body := `{"a":{"b":{"c":{"d":"deep"}}}}`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	a := data["a"].(map[string]interface{})
	b := a["b"].(map[string]interface{})
	c := b["c"].(map[string]interface{})
	if c["d"] != "MARKER" {
		t.Errorf("Expected a.b.c.d=MARKER, got %v", c["d"])
	}
}

func TestInjectBodyAllWithArray(t *testing.T) {
	body := `{"items":[{"id":1},{"id":2}],"count":2}`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	items := data["items"].([]interface{})
	first := items[0].(map[string]interface{})
	if first["id"] != "MARKER" {
		t.Errorf("Expected items[0].id=MARKER, got %v", first["id"])
	}
	if data["count"] != "MARKER" {
		t.Errorf("Expected count=MARKER, got %v", data["count"])
	}
}

func TestInjectBodyValueArrayElementOnly(t *testing.T) {
	// Path "items[0]" where array index is the last segment
	body := `{"items":["a","b","c"]}`
	result := InjectBodyValue(body, "items[0]", "MARKER", map[string]string{"Content-Type": "application/json"})

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	items := data["items"].([]interface{})
	if items[0] != "MARKER" {
		t.Errorf("Expected items[0]=MARKER, got %v", items[0])
	}
	if items[1] != "b" {
		t.Errorf("Expected items[1]=b, got %v", items[1])
	}
}

func TestInjectBodyValueArrayOutOfBounds(t *testing.T) {
	body := `{"items":["a","b"]}`
	result := InjectBodyValue(body, "items[5]", "MARKER", map[string]string{"Content-Type": "application/json"})

	// Should return body unchanged (index out of range)
	if result != body {
		t.Errorf("Expected body unchanged for out-of-bounds index, got: %s", result)
	}
}

func TestInjectBodyValueFormUnchanged(t *testing.T) {
	body := `name=test&email=test@example.com`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	if !strings.Contains(result, "name=MARKER") {
		t.Errorf("Expected name=MARKER in form body, got: %s", result)
	}
	if !strings.Contains(result, "email=test%40example.com") {
		t.Errorf("Expected email unchanged, got: %s", result)
	}
}

// --- multipart/form-data tests ---

func TestInjectBodyValueMultipart(t *testing.T) {
	body := buildMultipartBody(t, "field1", "value1", "field2", "value2")
	ct := "multipart/form-data; boundary=boundary123"
	result := InjectBodyValue(body, "field1", "MARKER", map[string]string{"Content-Type": ct})

	// Parse result and verify
	reader := multipart.NewReader(strings.NewReader(result), "boundary123")
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["field1"][0] != "MARKER" {
		t.Errorf("Expected field1=MARKER, got %s", form.Value["field1"][0])
	}
	if form.Value["field2"][0] != "value2" {
		t.Errorf("Expected field2=value2, got %s", form.Value["field2"][0])
	}
}

func TestInjectBodyValueMultipartNonExistent(t *testing.T) {
	body := buildMultipartBody(t, "field1", "value1")
	ct := "multipart/form-data; boundary=boundary123"
	result := InjectBodyValue(body, "nonexistent", "MARKER", map[string]string{"Content-Type": ct})

	reader := multipart.NewReader(strings.NewReader(result), "boundary123")
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["field1"][0] != "value1" {
		t.Errorf("Expected field1 unchanged, got %s", form.Value["field1"][0])
	}
}

func TestInjectBodyAllMultipart(t *testing.T) {
	body := buildMultipartBody(t, "a", "1", "b", "2")
	ct := "multipart/form-data; boundary=boundary123"
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": ct})

	reader := multipart.NewReader(strings.NewReader(result), "boundary123")
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["a"][0] != "MARKER" {
		t.Errorf("Expected a=MARKER, got %s", form.Value["a"][0])
	}
	if form.Value["b"][0] != "MARKER" {
		t.Errorf("Expected b=MARKER, got %s", form.Value["b"][0])
	}
}

func TestExtractBoundary(t *testing.T) {
	tests := []struct {
		ct       string
		expected string
	}{
		{"multipart/form-data; boundary=abc123", "abc123"},
		{`multipart/form-data; boundary="xyz"`, "xyz"},
		{"multipart/form-data; boundary=----WebKitFormBoundary", "----WebKitFormBoundary"},
		{"application/json", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractBoundary(tt.ct)
		if got != tt.expected {
			t.Errorf("extractBoundary(%q) = %q, want %q", tt.ct, got, tt.expected)
		}
	}
}

// --- XML tests ---

func TestInjectBodyValueXML(t *testing.T) {
	body := `<?xml version="1.0"?><root><name>test</name><age>25</age></root>`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/xml"})
	if !strings.Contains(result, "<name>MARKER</name>") {
		t.Errorf("Expected <name>MARKER</name>, got: %s", result)
	}
	if !strings.Contains(result, "<age>25</age>") {
		t.Errorf("Expected <age>25</age> unchanged, got: %s", result)
	}
}

func TestInjectBodyValueXMLWithAttributes(t *testing.T) {
	body := `<root><item id="1">old</item></root>`
	result := InjectBodyValue(body, "item", "MARKER", map[string]string{"Content-Type": "application/xml"})
	expected := `<root><item id="1">MARKER</item></root>`
	if result != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, result)
	}
}

func TestInjectBodyValueXMLNonExistent(t *testing.T) {
	body := `<root><name>test</name></root>`
	result := InjectBodyValue(body, "nonexistent", "MARKER", map[string]string{"Content-Type": "text/xml"})
	if result != body {
		t.Error("Expected body unchanged for non-existent element")
	}
}

func TestInjectBodyAllXML(t *testing.T) {
	body := `<root><a>1</a><b>2</b></root>`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/xml"})
	expected := `<root><a>MARKER</a><b>MARKER</b></root>`
	if result != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, result)
	}
}

// --- GraphQL tests ---

func TestInjectBodyValueGraphQL(t *testing.T) {
	body := `{"query":"query { user(name: \"test\") { id } }"}`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/graphql"})
	// Should contain MARKER and not contain "test"
	if !strings.Contains(result, "MARKER") {
		t.Errorf("Expected MARKER in GraphQL query, got: %s", result)
	}
	if strings.Contains(result, `"test"`) {
		t.Errorf("Expected original value replaced, got: %s", result)
	}
}

func TestInjectBodyAllGraphQL(t *testing.T) {
	body := `{"query":"query { user(name: \"test\", email: \"a@b.com\") { id } }"}`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/graphql"})
	// All string args should be replaced
	if strings.Contains(result, "test") || strings.Contains(result, "a@b.com") {
		t.Errorf("Expected all string args replaced, got: %s", result)
	}
}

// buildMultipartBody creates a multipart body with the given field/value pairs
// and a fixed boundary for predictable testing.
func buildMultipartBody(t *testing.T, pairs ...string) string {
	t.Helper()
	var buf strings.Builder
	writer := multipart.NewWriter(&buf)
	for i := 0; i < len(pairs); i += 2 {
		writer.WriteField(pairs[i], pairs[i+1])
	}
	writer.Close()
	// Replace all occurrences of the random boundary with a fixed one
	// The boundary appears as --BOUNDARY in the body, and also as --BOUNDARY-- at the end
	randomBoundary := writer.Boundary()
	body := buf.String()
	body = strings.ReplaceAll(body, randomBoundary, "boundary123")
	return body
}
