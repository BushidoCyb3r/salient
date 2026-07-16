// Package safefile writes sensitive local artifacts without following
// destination symlinks or leaving partial files behind.
package safefile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()

	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	tmp := ".salient-" + hex.EncodeToString(token[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, config.OutputFileMode)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if err := render(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmp, filepath.Base(abs)); err != nil {
		return err
	}
	if d, err := root.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// WriteFile atomically writes an in-memory artifact.
func WriteFile(path string, data []byte) error {
	return Write(path, func(w io.Writer) error {
		_, err := io.Copy(w, bytes.NewReader(data))
		return err
	})
}
