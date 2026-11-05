package integration

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Guard the distributed container's baseline without requiring a Docker daemon.
// Real browser execution is a separate CI container smoke test.
func TestContainerRuntimeSecurityPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	stages := strings.Split(text, "FROM ")
	if len(stages) < 3 {
		t.Fatal("multi-stage build required")
	}
	runtime := stages[2]
	if !regexp.MustCompile(`^alpine:[^\s]+@sha256:[a-f0-9]{64}`).MatchString(runtime) {
		t.Error("runtime base must be digest pinned")
	}
	if !strings.Contains(runtime, "chromium") {
		t.Error("runtime lacks Chromium")
	}
	if !regexp.MustCompile(`(?m)^USER (?:[1-9][0-9]*|xsscan)\s*$`).MatchString(runtime) {
		t.Error("runtime must use non-root user")
	}
	if strings.Contains(text, "chrome-no-sandbox") {
		t.Error("container must retain Chrome sandbox by default")
	}
}
