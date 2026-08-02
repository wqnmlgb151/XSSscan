package analyze

import (
	"testing"
)

func TestExtractJSONFlatParams(t *testing.T) {
	body := `{"q":"test","page":"1"}`
	params := extractJSONParams(body)

	if len(params) != 2 {
		t.Errorf("Expected 2 params, got %d", len(params))
	}

	found := false
	for _, p := range params {
		if p.Name == "q" && p.Value == "test" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected param q=test, got: %v", params)
	}
}

func TestExtractJSONNestedObject(t *testing.T) {
	body := `{"user":{"name":"test","email":"test@test.com"}}`
	params := extractJSONParams(body)

	foundName := false
	foundEmail := false
	for _, p := range params {
		if p.Name == "user.name" && p.Value == "test" {
			foundName = true
		}
		if p.Name == "user.email" && p.Value == "test@test.com" {
			foundEmail = true
		}
	}
	if !foundName {
		t.Errorf("Expected nested param user.name, got: %v", params)
	}
	if !foundEmail {
		t.Errorf("Expected nested param user.email, got: %v", params)
	}
}

func TestExtractJSONArrayOfObjects(t *testing.T) {
	body := `{"items":[{"id":1,"name":"first"},{"id":2,"name":"second"}]}`
	params := extractJSONParams(body)

	found := false
	for _, p := range params {
		if p.Name == "items[0].id" && p.Value == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected nested array param items[0].id, got: %v", params)
	}
}

func TestExtractJSONDeeplyNested(t *testing.T) {
	body := `{"a":{"b":{"c":{"d":"deep"}}}}`
	params := extractJSONParams(body)

	found := false
	for _, p := range params {
		if p.Name == "a.b.c.d" && p.Value == "deep" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected deeply nested param a.b.c.d, got: %v", params)
	}
}

func TestExtractJSONEmptyObject(t *testing.T) {
	body := `{}`
	params := extractJSONParams(body)

	if len(params) != 0 {
		t.Errorf("Expected 0 params for empty object, got %d", len(params))
	}
}

func TestExtractJSONInvalid(t *testing.T) {
	body := `not json`
	params := extractJSONParams(body)

	if len(params) != 0 {
		t.Errorf("Expected 0 params for invalid JSON, got %d", len(params))
	}
}
