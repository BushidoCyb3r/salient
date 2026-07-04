package safefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWritePreservesExistingFileOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Write(path, func(w io.Writer) error {
		_, _ = w.Write([]byte("partial"))
		return errors.New("render failed")
	})
	if err == nil {
		t.Fatal("Write returned nil error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("artifact = %q, want original", got)
	}
}

func TestWriteSupportsSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	err := Write(filepath.Join(linkedDir, "artifact"), func(w io.Writer) error {
		_, err := io.WriteString(w, "sensitive")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(realDir, "artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "sensitive" {
		t.Fatalf("artifact = %q, want sensitive", got)
	}
}

func TestWriteDoesNotFollowDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "artifact")
	if err := os.Symlink(victim, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := Write(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "replacement")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("symlink target = %q, want original", got)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement" {
		t.Fatalf("artifact = %q, want replacement", got)
	}
}
