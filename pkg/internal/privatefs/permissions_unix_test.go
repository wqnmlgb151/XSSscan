//go:build !windows

package privatefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectSymlinkWithoutChangingTarget(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("secret")); err == nil {
		t.Fatal("symlink output accepted")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "keep" {
		t.Fatal("symlink target changed")
	}
}
