package privatefs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateAtomicReplacementAndFailureCleanup(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "report.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("synthetic-private-evidence")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "synthetic-private-evidence" {
		t.Fatalf("replacement: %q %v", data, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatalf("mode %o", info.Mode().Perm())
		}
	}
	if err := WriteFile(parent, []byte("must-not-write")); err == nil {
		t.Fatal("directory accepted")
	}
	if err := WriteFile(filepath.Join(parent, "missing", "report"), []byte("must-not-write")); err == nil {
		t.Fatal("missing parent accepted")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v", entries)
	}
}

func TestPrivateDirectoryIsolation(t *testing.T) {
	parent := t.TempDir()
	one, err := TempDir(parent, "proof-")
	if err != nil {
		t.Fatal(err)
	}
	two, err := TempDir(parent, "proof-")
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("reused temporary directory")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(one)
		if info.Mode().Perm() != 0700 {
			t.Fatalf("directory mode %o", info.Mode().Perm())
		}
	}
}

func TestReplacementDoesNotModifyHardlinkTarget(t *testing.T) {
	dir := t.TempDir()
	original, output := filepath.Join(dir, "original"), filepath.Join(dir, "report")
	if err := os.WriteFile(original, []byte("keep-original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, output); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(output, []byte("private-report")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(original)
	if err != nil || string(data) != "keep-original" {
		t.Fatalf("hardlink original changed: %q %v", data, err)
	}
}
