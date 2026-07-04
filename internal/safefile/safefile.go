// Package safefile writes sensitive local artifacts without following
// destination symlinks or leaving partial files behind.
package safefile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BushidoCyb3r/defilade/internal/config"
)

// Write renders an artifact to a temporary file, then atomically replaces path.
func Write(path string, render func(io.Writer) error) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := rejectSymlinks(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, config.OutputDirMode); err != nil {
		return err
	}
	if err := rejectSymlinks(dir); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, ".defilade-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(config.OutputFileMode); err != nil {
		_ = f.Close()
		return err
	}
	if err := render(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, abs)
}

// WriteFile atomically writes an in-memory artifact.
func WriteFile(path string, data []byte) error {
	return Write(path, func(w io.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(data))
		return err
	})
}

func rejectSymlinks(path string) error {
	for {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output directory %q is a symbolic link", path)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
