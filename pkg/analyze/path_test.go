package analyze

import (
	"github.com/xsscan/xsscan/pkg/internal/request"
	"testing"
)

func TestExtractPathParams_EncodedSlashIndexes(t *testing.T) {
	target := "https://example.com/a%2Fb/name%21"
	params := extractPathParams(target)
	found := false
	for _, param := range params {
		if param.Value != "name!" {
			continue
		}
		found = true
		if param.Name != "path[2]" {
			t.Fatalf("Wrong segment index: %+v", param)
		}
		got, err := request.InjectPathValue(target, param.Name, param.Value, "proof")
		if err != nil || got != "https://example.com/a%2Fb/proof" {
			t.Fatalf("Wrong injected path: %s, %v", got, err)
		}
	}
	if !found {
		t.Fatal("Dynamic path parameter not discovered")
	}
}
