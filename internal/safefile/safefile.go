// Package safefile writes sensitive local artifacts without following
// destination symlinks or leaving partial files behind.
package safefile

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/BushidoCyb3r/salient/internal/config"
)

// Write renders an artifact to a temporary file, then atomically replaces path.
func Write(path string, render func(io.Writer) error) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, config.OutputDirMode); err != nil {
		return err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	abs = filepath.Join(dir, filepath.Base(abs))

	f, err := os.CreateTemp(dir, ".salient-*")
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
