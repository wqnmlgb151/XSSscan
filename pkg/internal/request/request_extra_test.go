package request

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/xsscan/xsscan/pkg/httpclient"
	"github.com/xsscan/xsscan/pkg/model"
)

// ─────────────────────────────────────────────────────────────────────
// CloneHeaders
// ─────────────────────────────────────────────────────────────────────

func TestCloneHeadersNil(t *testing.T) {
	if CloneHeaders(nil) != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestCloneHeadersModifyIndependent(t *testing.T) {
	src := map[string]string{"a": "1", "b": "2"}
	dst := CloneHeaders(src)
	dst["a"] = "changed"
	if src["a"] != "1" {
		t.Error("Modifying dst should not affect src")
	}
}

func TestCloneHeadersEmpty(t *testing.T) {
	src := map[string]string{}
	dst := CloneHeaders(src)
	if dst == nil {
		t.Error("Expected non-nil map for empty input")
	}
	if len(dst) != 0 {
		t.Errorf("Expected empty map, got %v", dst)
	}
}

// ─────────────────────────────────────────────────────────────────────
// CloneCookies
// ─────────────────────────────────────────────────────────────────────

func TestCloneCookiesNil(t *testing.T) {
	if CloneCookies(nil) != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestCloneCookiesModifyIndependent(t *testing.T) {
	src := []*http.Cookie{{Name: "session", Value: "abc"}}
	dst := CloneCookies(src)
	dst[0].Value = "changed"
	if src[0].Value != "abc" {
		t.Error("Modifying dst should not affect src")
	}
}

func TestCloneCookiesNilElement(t *testing.T) {
	src := []*http.Cookie{{Name: "a", Value: "1"}, nil, {Name: "b", Value: "2"}}
	dst := CloneCookies(src)
	if len(dst) != 3 {
		t.Fatalf("Expected length 3, got %d", len(dst))
	}
	if dst[1] != nil {
		t.Error("Expected nil element preserved at index 1")
	}
	// Verify non-nil elements are independent copies
	dst[0].Value = "changed"
	if src[0].Value != "1" {
		t.Error("Modifying dst element should not affect src")
	}
}

// ─────────────────────────────────────────────────────────────────────
// HeaderMap
// ─────────────────────────────────────────────────────────────────────

func TestHeaderMapMultiValue(t *testing.T) {
	h := http.Header{}
	h.Add("Accept", "text/html")
	h.Add("Accept", "application/json")
	m := HeaderMap(h)
	if m["Accept"] != "text/html" {
		t.Errorf("Expected first value 'text/html', got %q", m["Accept"])
	}
}

func TestHeaderMapEmpty(t *testing.T) {
	m := HeaderMap(http.Header{})
	if len(m) != 0 {
		t.Errorf("Expected empty map, got %v", m)
	}
}

func TestHeaderMapNil(t *testing.T) {
	m := HeaderMap(nil)
	if len(m) != 0 {
		t.Errorf("Expected empty map for nil header, got %v", m)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ApplyHeaders
// ─────────────────────────────────────────────────────────────────────

func TestApplyHeadersDefaultUA(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	ApplyHeaders(req, model.Target{}, false)
	if got := req.Header.Get("User-Agent"); got != httpclient.DefaultUA {
		t.Errorf("Expected default UA %q, got %q", httpclient.DefaultUA, got)
	}
}

func TestApplyHeadersRandomUA(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	ApplyHeaders(req, model.Target{}, true)
	ua := req.Header.Get("User-Agent")
	if ua == "" {
		t.Error("Expected non-empty UA for randomUA=true")
	}
}

func TestApplyHeadersRandomUADifferent(t *testing.T) {
	// With 50+ UA entries, 100 iterations should yield >1 unique value.
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		req, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatal(err)
		}
		ApplyHeaders(req, model.Target{}, true)
		seen[req.Header.Get("User-Agent")] = true
	}
	if len(seen) < 2 {
		t.Errorf("Expected at least 2 different UAs in 100 tries, got %d", len(seen))
	}
}

func TestApplyHeadersProxyAuth(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	ApplyHeaders(req, model.Target{ProxyAuth: "Basic dXNlcjpwYXNz"}, false)
	if got := req.Header.Get("Proxy-Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Errorf("Expected Proxy-Authorization header, got %q", got)
	}
}

func TestApplyHeadersCookies(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{
		Cookies: []*http.Cookie{
			{Name: "session", Value: "abc123"},
			{Name: "csrf", Value: "token456"},
		},
	}
	ApplyHeaders(req, target, false)
	cookies := req.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("Expected 2 cookies, got %d", len(cookies))
	}
	// Map by name since order from req.Cookies() may vary.
	byName := map[string]string{}
	for _, c := range cookies {
		byName[c.Name] = c.Value
	}
	if byName["session"] != "abc123" {
		t.Errorf("Expected session=abc123, got %q", byName["session"])
	}
	if byName["csrf"] != "token456" {
		t.Errorf("Expected csrf=token456, got %q", byName["csrf"])
	}
}

func TestApplyHeadersCustomHeaders(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{
		Headers: map[string]string{
			"X-Custom": "value",
			"Accept":   "application/json",
		},
	}
	ApplyHeaders(req, target, false)
	if got := req.Header.Get("X-Custom"); got != "value" {
		t.Errorf("Expected X-Custom=value, got %q", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Expected Accept=application/json, got %q", got)
	}
}

func TestApplyHeadersUANotOverridden(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{
		Headers: map[string]string{"User-Agent": "CustomBot/1.0"},
	}
	ApplyHeaders(req, target, false)
	if got := req.Header.Get("User-Agent"); got != "CustomBot/1.0" {
		t.Errorf("Expected CustomBot/1.0, got %q", got)
	}
}

func TestApplyHeadersContentTypeWhenBodyPresent(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{
		Body:    `{"key":"val"}`,
		Headers: map[string]string{"Content-Type": "application/json"},
	}
	ApplyHeaders(req, target, false)
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Expected Content-Type=application/json, got %q", got)
	}
}

func TestApplyHeadersContentTypeWhenNoBody(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{
		Headers: map[string]string{"Content-Type": "application/json"},
	}
	ApplyHeaders(req, target, false)
	// The final `for k, v := range target.Headers` loop sets ALL custom headers
	// regardless of body presence, so Content-Type IS set even with empty body.
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Expected Content-Type=application/json (custom header loop), got %q", got)
	}
}

func TestApplyHeadersCustomUADoesNotOverrideWithRandom(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := model.Target{
		Headers: map[string]string{"User-Agent": "MyBot/2.0"},
	}
	ApplyHeaders(req, target, true)
	if got := req.Header.Get("User-Agent"); got != "MyBot/2.0" {
		t.Errorf("Expected MyBot/2.0 (should not be overridden by random), got %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// parseKeyPath
// ─────────────────────────────────────────────────────────────────────

func TestParseKeyPathSimple(t *testing.T) {
	got := parseKeyPath("a.b.c")
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeyPath(%q) = %v, want %v", "a.b.c", got, want)
	}
}

func TestParseKeyPathArrayIndex(t *testing.T) {
	got := parseKeyPath("items[0].name")
	want := []string{"items", "0", "name"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeyPath(%q) = %v, want %v", "items[0].name", got, want)
	}
}

func TestParseKeyPathLeadingBracket(t *testing.T) {
	got := parseKeyPath("[0]")
	want := []string{"0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeyPath(%q) = %v, want %v", "[0]", got, want)
	}
}

func TestParseKeyPathEmpty(t *testing.T) {
	got := parseKeyPath("")
	if len(got) != 0 {
		t.Errorf("parseKeyPath(%q) = %v, want empty", "", got)
	}
}

func TestParseKeyPathSingleKey(t *testing.T) {
	got := parseKeyPath("name")
	want := []string{"name"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeyPath(%q) = %v, want %v", "name", got, want)
	}
}

func TestParseKeyPathConsecutiveDots(t *testing.T) {
	// "a..b" → segments: ["a", "b"] (empty segments from consecutive dots are skipped)
	got := parseKeyPath("a..b")
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeyPath(%q) = %v, want %v", "a..b", got, want)
	}
}

func TestParseKeyPathNestedArray(t *testing.T) {
	got := parseKeyPath("data[0][1]")
	want := []string{"data", "0", "1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseKeyPath(%q) = %v, want %v", "data[0][1]", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────
// setNestedValue
// ─────────────────────────────────────────────────────────────────────

func TestSetNestedValueCreateMissingFalse(t *testing.T) {
	data := map[string]interface{}{"a": "x"}
	// Path has 2 segments: "b" is intermediate (missing), "c" is leaf.
	// With createMissing=false, the missing intermediate "b" blocks the set.
	ok := setNestedValue(data, []string{"b", "c"}, "val", false)
	if ok {
		t.Error("Expected false for missing intermediate key with createMissing=false")
	}
	if _, exists := data["b"]; exists {
		t.Error("Expected key 'b' not to be created")
	}
}

func TestSetNestedValueCreateMissingTrue(t *testing.T) {
	data := map[string]interface{}{}
	ok := setNestedValue(data, []string{"new_key"}, "val", true)
	if !ok {
		t.Error("Expected true for new key with createMissing=true")
	}
	if data["new_key"] != "val" {
		t.Errorf("Expected new_key=val, got %v", data["new_key"])
	}
}

func TestSetNestedValueEmptyPath(t *testing.T) {
	data := map[string]interface{}{"a": "x"}
	ok := setNestedValue(data, []string{}, "val", true)
	if ok {
		t.Error("Expected false for empty path")
	}
}

func TestSetNestedValuePrimitiveIntermediate(t *testing.T) {
	data := map[string]interface{}{"a": "string_value"}
	// Path "a.b" where "a" is a string, not a map → cannot descend.
	ok := setNestedValue(data, []string{"a", "b"}, "val", true)
	if ok {
		t.Error("Expected false when intermediate value is a primitive")
	}
}

func TestSetNestedValueNegativeArrayIndex(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}
	ok := setNestedValue(data, []string{"items", "-1"}, "val", true)
	if ok {
		t.Error("Expected false for negative array index")
	}
}

func TestSetNestedValueArrayIndexNonNumeric(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{"a", "b"},
	}
	// Path "items[abc]" where next segment after array is non-numeric
	ok := setNestedValue(data, []string{"items", "abc"}, "val", true)
	if ok {
		t.Error("Expected false for non-numeric array index")
	}
}

func TestSetNestedValueArrayDescendThenSet(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"name": "first"},
			map[string]interface{}{"name": "second"},
		},
	}
	ok := setNestedValue(data, []string{"items", "1", "name"}, "MODIFIED", true)
	if !ok {
		t.Error("Expected true for valid array descend path")
	}
	items := data["items"].([]interface{})
	second := items[1].(map[string]interface{})
	if second["name"] != "MODIFIED" {
		t.Errorf("Expected name=MODIFIED, got %v", second["name"])
	}
	// Verify first element is unchanged
	first := items[0].(map[string]interface{})
	if first["name"] != "first" {
		t.Errorf("Expected first.name=first unchanged, got %v", first["name"])
	}
}

func TestSetNestedValueArrayElementNotMap(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{"a", "b", "c"},
	}
	// Path "items[0].name" where items[0] is a string, not a map.
	ok := setNestedValue(data, []string{"items", "0", "name"}, "val", true)
	if ok {
		t.Error("Expected false when array element is not a map")
	}
}

func TestSetNestedValueCreateMissingProducesMap(t *testing.T) {
	// When createMissing=true and a missing key is followed by what looks like
	// an array index, the function creates an intermediate MAP (not an array).
	// The "index" becomes a map key. This documents that behavior.
	data := map[string]interface{}{}
	ok := setNestedValue(data, []string{"items", "0"}, "val", true)
	if !ok {
		t.Error("Expected true — createMissing creates a map and sets key '0'")
	}
	items, ok := data["items"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected 'items' to be a map (not an array)")
	}
	if items["0"] != "val" {
		t.Errorf("Expected items.0=val, got %v", items["0"])
	}
}

func TestInjectBodyAllJSONArrayOfPrimitives(t *testing.T) {
	// replaceLeaves recurses into map elements of arrays but skips primitives.
	body := `{"items":["a","b","c"]}`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/json"})
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	items := data["items"].([]interface{})
	if items[0] != "a" || items[1] != "b" || items[2] != "c" {
		t.Errorf("Expected primitive array elements unchanged, got %v", items)
	}
}

// ─────────────────────────────────────────────────────────────────────
// InjectBodyValue — edge cases & uncovered paths
// ─────────────────────────────────────────────────────────────────────

func TestInjectBodyValueEmptyJSONBody(t *testing.T) {
	// Empty body {} with createMissing=true should create the field.
	body := `{}`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/json"})
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if data["name"] != "MARKER" {
		t.Errorf("Expected name=MARKER, got %v", data["name"])
	}
}

func TestInjectBodyValueInvalidJSON(t *testing.T) {
	body := `not valid json`
	result := InjectBodyValue(body, "key", "MARKER", map[string]string{"Content-Type": "application/json"})
	if result != body {
		t.Error("Expected body unchanged for invalid JSON")
	}
}

func TestInjectBodyValueJSONArrayRoot(t *testing.T) {
	// Valid JSON but not an object — cannot unmarshal into map[string]interface{}.
	body := `[1,2,3]`
	result := InjectBodyValue(body, "key", "MARKER", map[string]string{"Content-Type": "application/json"})
	if result != body {
		t.Error("Expected body unchanged for JSON array root")
	}
}

func TestInjectBodyValueFormURLParseError(t *testing.T) {
	body := "%zz" // invalid percent-encoding
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if result != body {
		t.Error("Expected body unchanged for invalid form-urlencoded")
	}
}

func TestInjectBodyValueMultipartWithFile(t *testing.T) {
	var buf strings.Builder
	writer := multipart.NewWriter(&buf)
	writer.WriteField("textfield", "textvalue")
	fw, err := writer.CreateFormFile("filefield", "test.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("file content"))
	writer.Close()
	ct := "multipart/form-data; boundary=" + writer.Boundary()

	result := InjectBodyValue(buf.String(), "textfield", "MARKER", map[string]string{"Content-Type": ct})

	reader := multipart.NewReader(strings.NewReader(result), writer.Boundary())
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["textfield"][0] != "MARKER" {
		t.Errorf("Expected textfield=MARKER, got %q", form.Value["textfield"][0])
	}
	// File field should be preserved
	if form.File["filefield"][0].Filename != "test.txt" {
		t.Errorf("Expected filefield filename=test.txt, got %q", form.File["filefield"][0].Filename)
	}
}

func TestInjectBodyValueMultipartNoBoundary(t *testing.T) {
	body := "some body"
	ct := "multipart/form-data" // no boundary
	result := InjectBodyValue(body, "field", "MARKER", map[string]string{"Content-Type": ct})
	if result != body {
		t.Error("Expected body unchanged for multipart with no boundary")
	}
}

func TestInjectBodyValueXMLInvalid(t *testing.T) {
	// Not XML at all — regex won't match.
	body := "this is not xml at all"
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/xml"})
	if result != body {
		t.Error("Expected body unchanged for non-XML content")
	}
}

func TestInjectBodyValueGraphQLInvalidJSON(t *testing.T) {
	body := `not json`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/graphql"})
	if result != body {
		t.Error("Expected body unchanged for invalid GraphQL JSON")
	}
}

func TestInjectBodyValueGraphQLNoQuery(t *testing.T) {
	body := `{"variables":{"x":1}}`
	result := InjectBodyValue(body, "name", "MARKER", map[string]string{"Content-Type": "application/graphql"})
	if result != body {
		t.Error("Expected body unchanged when no query field in GraphQL body")
	}
}

func TestInjectBodyValueGraphQLUnquoted(t *testing.T) {
	body := `{"query":"query { user(id: 123) { name } }"}`
	result := InjectBodyValue(body, "id", "MARKER", map[string]string{"Content-Type": "application/graphql"})
	if !strings.Contains(result, "MARKER") {
		t.Errorf("Expected MARKER in GraphQL query for unquoted value, got: %s", result)
	}
	if strings.Contains(result, "123") {
		t.Errorf("Expected original unquoted value replaced, got: %s", result)
	}
}

func TestInjectBodyValueArrayTypeMismatch(t *testing.T) {
	// Path tries to descend into array element as map, but it's a primitive.
	body := `{"items":["a","b","c"]}`
	result := InjectBodyValue(body, "items[0].name", "MARKER", map[string]string{"Content-Type": "application/json"})
	if result != body {
		t.Error("Expected body unchanged when array element is a primitive")
	}
}

// ─────────────────────────────────────────────────────────────────────
// InjectBodyAll — edge cases & uncovered paths
// ─────────────────────────────────────────────────────────────────────

func TestInjectBodyAllInvalidJSON(t *testing.T) {
	body := `not valid json`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/json"})
	if result != body {
		t.Error("Expected body unchanged for invalid JSON")
	}
}

func TestInjectBodyAllJSONArrayRoot(t *testing.T) {
	body := `[1,2,3]`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/json"})
	if result != body {
		t.Error("Expected body unchanged for JSON array root")
	}
}

func TestInjectBodyAllMultipartNoBoundary(t *testing.T) {
	body := "some body"
	ct := "multipart/form-data" // no boundary
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": ct})
	if result != body {
		t.Error("Expected body unchanged for multipart with no boundary")
	}
}

func TestInjectBodyAllFormURLParseError(t *testing.T) {
	body := "%zz"
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if result != body {
		t.Error("Expected body unchanged for invalid form-urlencoded")
	}
}

func TestInjectBodyAllGraphQLInvalidJSON(t *testing.T) {
	body := `not json`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/graphql"})
	if result != body {
		t.Error("Expected body unchanged for invalid GraphQL JSON")
	}
}

func TestInjectBodyAllGraphQLNoQuery(t *testing.T) {
	body := `{"variables":{"x":1}}`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/graphql"})
	if result != body {
		t.Error("Expected body unchanged when no query field in GraphQL body")
	}
}

func TestInjectBodyAllXMLWithEmptyElement(t *testing.T) {
	// Empty elements like <empty></empty> should NOT be replaced (m[3] != "" guard).
	body := `<root><a>1</a><empty></empty><b>2</b></root>`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/xml"})
	expected := `<root><a>MARKER</a><empty></empty><b>MARKER</b></root>`
	if result != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, result)
	}
}

func TestInjectBodyAllXMLWithSelfClosing(t *testing.T) {
	// Self-closing tags are not matched by the open/close regex pattern.
	body := `<root><a>1</a><br/><b>2</b></root>`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/xml"})
	expected := `<root><a>MARKER</a><br/><b>MARKER</b></root>`
	if result != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, result)
	}
}

func TestInjectBodyAllUnknownContentType(t *testing.T) {
	// Unknown CT defaults to form-urlencoded.
	body := `key=value`
	result := InjectBodyAll(body, "MARKER", map[string]string{"Content-Type": "application/unknown"})
	if !strings.Contains(result, "key=MARKER") {
		t.Errorf("Expected key=MARKER for unknown CT (form default), got: %s", result)
	}
}

// ─────────────────────────────────────────────────────────────────────
// InjectBodyMarkers
// ─────────────────────────────────────────────────────────────────────

func TestInjectBodyMarkersJSON(t *testing.T) {
	body := `{"name":"test","email":"test@example.com"}`
	markers := map[string]string{
		"name":  "MARKER_NAME",
		"email": "MARKER_EMAIL",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/json"})
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if data["name"] != "MARKER_NAME" {
		t.Errorf("Expected name=MARKER_NAME, got %v", data["name"])
	}
	if data["email"] != "MARKER_EMAIL" {
		t.Errorf("Expected email=MARKER_EMAIL, got %v", data["email"])
	}
}

func TestInjectBodyMarkersPartialKeys(t *testing.T) {
	body := `{"name":"test","email":"test@example.com"}`
	markers := map[string]string{"name": "MARKER_NAME"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/json"})
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if data["name"] != "MARKER_NAME" {
		t.Errorf("Expected name=MARKER_NAME, got %v", data["name"])
	}
	// email is not in markers → should remain unchanged
	if data["email"] != "test@example.com" {
		t.Errorf("Expected email unchanged, got %v", data["email"])
	}
}

func TestInjectBodyMarkersInvalidJSON(t *testing.T) {
	body := `not valid json`
	markers := map[string]string{"name": "MARKER"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/json"})
	if result != body {
		t.Error("Expected body unchanged for invalid JSON")
	}
}

func TestInjectBodyMarkersEmptyMarkers(t *testing.T) {
	body := `{"name":"test"}`
	markers := map[string]string{}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/json"})
	// No markers → body should be unchanged (or at least still valid JSON with original values)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	if data["name"] != "test" {
		t.Errorf("Expected name unchanged when markers empty, got %v", data["name"])
	}
}

func TestInjectBodyMarkersMultipart(t *testing.T) {
	body := buildMultipartBody(t, "field1", "value1", "field2", "value2")
	ct := "multipart/form-data; boundary=boundary123"
	markers := map[string]string{
		"field1": "MARKER1",
		"field2": "MARKER2",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": ct})
	reader := multipart.NewReader(strings.NewReader(result), "boundary123")
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["field1"][0] != "MARKER1" {
		t.Errorf("Expected field1=MARKER1, got %q", form.Value["field1"][0])
	}
	if form.Value["field2"][0] != "MARKER2" {
		t.Errorf("Expected field2=MARKER2, got %q", form.Value["field2"][0])
	}
}

func TestInjectBodyMarkersMultipartPartialKeys(t *testing.T) {
	body := buildMultipartBody(t, "field1", "value1", "field2", "value2")
	ct := "multipart/form-data; boundary=boundary123"
	markers := map[string]string{"field1": "MARKER1"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": ct})
	reader := multipart.NewReader(strings.NewReader(result), "boundary123")
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["field1"][0] != "MARKER1" {
		t.Errorf("Expected field1=MARKER1, got %q", form.Value["field1"][0])
	}
	// field2 not in markers → unchanged
	if form.Value["field2"][0] != "value2" {
		t.Errorf("Expected field2=value2 unchanged, got %q", form.Value["field2"][0])
	}
}

func TestInjectBodyMarkersMultipartWithFile(t *testing.T) {
	var buf strings.Builder
	writer := multipart.NewWriter(&buf)
	writer.WriteField("textfield", "textvalue")
	fw, err := writer.CreateFormFile("filefield", "upload.txt")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte("file content here"))
	writer.Close()
	boundary := writer.Boundary()
	body := buf.String()
	ct := "multipart/form-data; boundary=" + boundary

	markers := map[string]string{
		"textfield": "MARKER_TEXT",
		"filefield": "MARKER_FILE",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": ct})
	reader := multipart.NewReader(strings.NewReader(result), boundary)
	form, err := reader.ReadForm(1024 * 1024)
	if err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if form.Value["textfield"][0] != "MARKER_TEXT" {
		t.Errorf("Expected textfield=MARKER_TEXT, got %q", form.Value["textfield"][0])
	}
	// File field should be preserved with original filename
	if form.File["filefield"][0].Filename != "upload.txt" {
		t.Errorf("Expected filefield filename=upload.txt, got %q", form.File["filefield"][0].Filename)
	}
}

func TestInjectBodyMarkersXML(t *testing.T) {
	body := `<root><name>test</name><age>25</age></root>`
	markers := map[string]string{
		"name": "MARKER_NAME",
		"age":  "MARKER_AGE",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/xml"})
	expected := `<root><name>MARKER_NAME</name><age>MARKER_AGE</age></root>`
	if result != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, result)
	}
}

func TestInjectBodyMarkersXMLPartialKeys(t *testing.T) {
	body := `<root><name>test</name><age>25</age></root>`
	markers := map[string]string{"name": "MARKER_NAME"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/xml"})
	expected := `<root><name>MARKER_NAME</name><age>25</age></root>`
	if result != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, result)
	}
}

func TestInjectBodyMarkersGraphQL(t *testing.T) {
	body := `{"query":"query { user(name: \"test\", email: \"a@b.com\") { id } }"}`
	markers := map[string]string{
		"name":  "MARKER_NAME",
		"email": "MARKER_EMAIL",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/graphql"})
	if !strings.Contains(result, "MARKER_NAME") || !strings.Contains(result, "MARKER_EMAIL") {
		t.Errorf("Expected both markers in GraphQL query, got: %s", result)
	}
	if strings.Contains(result, `"test"`) || strings.Contains(result, `"a@b.com"`) {
		t.Errorf("Expected original values replaced, got: %s", result)
	}
}

func TestInjectBodyMarkersGraphQLPartialKeys(t *testing.T) {
	body := `{"query":"query { user(name: \"test\", email: \"a@b.com\") { id } }"}`
	markers := map[string]string{"name": "MARKER_NAME"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/graphql"})
	if !strings.Contains(result, "MARKER_NAME") {
		t.Errorf("Expected MARKER_NAME in query, got: %s", result)
	}
	// email not in markers → should remain unchanged (parse JSON to verify)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON result: %v", err)
	}
	query, _ := data["query"].(string)
	if !strings.Contains(query, "a@b.com") {
		t.Errorf("Expected email 'a@b.com' unchanged in query, got: %s", query)
	}
}

func TestInjectBodyMarkersGraphQLUnquoted(t *testing.T) {
	body := `{"query":"query { user(id: 123) { name } }"}`
	markers := map[string]string{"id": "MARKER_ID"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/graphql"})
	if !strings.Contains(result, "MARKER_ID") {
		t.Errorf("Expected MARKER_ID in query for unquoted value, got: %s", result)
	}
	if strings.Contains(result, "123") {
		t.Errorf("Expected original unquoted value replaced, got: %s", result)
	}
}

func TestInjectBodyMarkersGraphQLInvalidJSON(t *testing.T) {
	body := `not json`
	markers := map[string]string{"name": "MARKER"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/graphql"})
	if result != body {
		t.Error("Expected body unchanged for invalid GraphQL JSON")
	}
}

func TestInjectBodyMarkersGraphQLNoQuery(t *testing.T) {
	body := `{"variables":{"x":1}}`
	markers := map[string]string{"name": "MARKER"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/graphql"})
	if result != body {
		t.Error("Expected body unchanged when no query field")
	}
}

func TestInjectBodyMarkersFormURL(t *testing.T) {
	body := `name=test&email=test@example.com`
	markers := map[string]string{
		"name":  "MARKER_NAME",
		"email": "MARKER_EMAIL",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if !strings.Contains(result, "name=MARKER_NAME") {
		t.Errorf("Expected name=MARKER_NAME, got: %s", result)
	}
	if !strings.Contains(result, "email=MARKER_EMAIL") {
		t.Errorf("Expected email=MARKER_EMAIL, got: %s", result)
	}
}

func TestInjectBodyMarkersFormURLPartialKeys(t *testing.T) {
	body := `name=test&email=test@example.com`
	markers := map[string]string{"name": "MARKER_NAME"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if !strings.Contains(result, "name=MARKER_NAME") {
		t.Errorf("Expected name=MARKER_NAME, got: %s", result)
	}
	// email not in markers → unchanged
	if !strings.Contains(result, "email=test") {
		t.Errorf("Expected email unchanged, got: %s", result)
	}
}

func TestInjectBodyMarkersFormURLParseError(t *testing.T) {
	body := "%zz"
	markers := map[string]string{"name": "MARKER"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if result != body {
		t.Error("Expected body unchanged for invalid form-urlencoded")
	}
}

func TestInjectBodyMarkersNoMatchingKeysInBody(t *testing.T) {
	// Markers reference keys that don't exist in the body.
	body := `{"name":"test"}`
	markers := map[string]string{"nonexistent": "MARKER"}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/json"})
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	// name should remain unchanged since it's not in markers
	if data["name"] != "test" {
		t.Errorf("Expected name unchanged, got %v", data["name"])
	}
}

func TestInjectBodyMarkersNestedJSON(t *testing.T) {
	body := `{"user":{"name":"test","email":"test@example.com"},"active":true}`
	markers := map[string]string{
		"name":   "MARKER_NAME",
		"active": "MARKER_ACTIVE",
	}
	result := InjectBodyMarkers(body, markers, map[string]string{"Content-Type": "application/json"})
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}
	user := data["user"].(map[string]interface{})
	if user["name"] != "MARKER_NAME" {
		t.Errorf("Expected user.name=MARKER_NAME, got %v", user["name"])
	}
	// email not in markers → unchanged
	if user["email"] != "test@example.com" {
		t.Errorf("Expected user.email unchanged, got %v", user["email"])
	}
	if data["active"] != "MARKER_ACTIVE" {
		t.Errorf("Expected active=MARKER_ACTIVE, got %v", data["active"])
	}
}
