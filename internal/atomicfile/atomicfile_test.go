package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteAtomically pins the contract: the file lands with the given bytes and
// mode, and no temporary file is left behind in the directory.
func TestWriteAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.go")
	if err := Write(path, []byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello\n" {
		t.Errorf("content = %q, want %q", got, "hello\n")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
	left, err := filepath.Glob(filepath.Join(dir, "*.tmp*"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

// TestWriteReplacesExisting pins that a second write overwrites atomically and
// does not append.
func TestWriteReplacesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.go")
	if err := Write(path, []byte("first")); err != nil {
		t.Fatalf("Write first: %v", err)
	}
	if err := Write(path, []byte("second")); err != nil {
		t.Fatalf("Write second: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(got)) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
}

// TestWriteMissingDirFails pins that a write into a nonexistent directory fails
// and does not create the directory: callers do their own MkdirAll.
func TestWriteMissingDirFails(t *testing.T) {
	dir := t.TempDir()
	err := Write(filepath.Join(dir, "missing", "out.go"), []byte("x"))
	if err == nil {
		t.Fatal("Write into a missing directory succeeded, want error")
	}
	if !strings.Contains(err.Error(), "atomicfile:") {
		t.Errorf("error %q should carry the atomicfile: prefix", err)
	}
}
