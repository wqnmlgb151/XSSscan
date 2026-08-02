package analyze

import (
	"testing"

	"github.com/xsscan/xsscan/pkg/model"
)

func TestFindReflectionsExactMatch(t *testing.T) {
	ra := NewReflectionAnalyzer()
	body := `<html><body>xsscanAbCdEfGhIj</body></html>`

	refs := ra.FindReflections(body, model.Parameter{
		Name:  "q",
		Value: "xsscanAbCdEfGhIj",
	})

	if len(refs) != 1 {
		t.Errorf("Expected 1 reflection for exact match, got %d", len(refs))
	}
}

func TestFindReflectionsURLEncoded(t *testing.T) {
	ra := NewReflectionAnalyzer()
	// URL-encoded marker
	body := `<html><body>xsscan%41bCdEfGhIj</body></html>`

	refs := ra.FindReflections(body, model.Parameter{
		Name:  "q",
		Value: "xsscanAbCdEfGhIj",
	})

	if len(refs) != 1 {
		t.Errorf("Expected 1 reflection for URL-encoded match, got %d", len(refs))
	}
}

func TestFindReflectionsHTMLEncoded(t *testing.T) {
	ra := NewReflectionAnalyzer()
	// HTML-entity-encoded marker (the < in marker would be encoded)
	body := `<html><body>xsscan&lt;AbCdEfGhIj</body></html>`

	refs := ra.FindReflections(body, model.Parameter{
		Name:  "q",
		Value: "xsscan<AbCdEfGhIj",
	})

	if len(refs) != 1 {
		t.Errorf("Expected 1 reflection for HTML-entity-encoded match, got %d", len(refs))
	}
}

func TestFindReflectionsCaseChanged(t *testing.T) {
	ra := NewReflectionAnalyzer()
	// Server converted to uppercase
	body := `<html><body>XSSCANABCDEFGHIJ</body></html>`

	refs := ra.FindReflections(body, model.Parameter{
		Name:  "q",
		Value: "xsscanAbCdEfGhIj",
	})

	if len(refs) != 1 {
		t.Errorf("Expected 1 reflection for case-changed match, got %d", len(refs))
	}
}

func TestFindReflectionsNotFound(t *testing.T) {
	ra := NewReflectionAnalyzer()
	body := `<html><body>Hello World</body></html>`

	refs := ra.FindReflections(body, model.Parameter{
		Name:  "q",
		Value: "xsscanAbCdEfGhIj",
	})

	if len(refs) != 0 {
		t.Errorf("Expected 0 reflections for absent marker, got %d", len(refs))
	}
}

func TestFindReflectionsEmptyValue(t *testing.T) {
	ra := NewReflectionAnalyzer()
	body := `<html><body>anything</body></html>`

	refs := ra.FindReflections(body, model.Parameter{
		Name:  "q",
		Value: "",
	})

	if len(refs) != 0 {
		t.Errorf("Expected 0 reflections for empty value, got %d", len(refs))
	}
}
