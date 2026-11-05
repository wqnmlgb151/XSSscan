package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishedModulePathMatchesRepository(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(strings.SplitN(string(contents), "\n", 2)[0]) != "module github.com/wqnmlgb151/XSSscan" {
		t.Fatal("module path differs from published repository")
	}
}
