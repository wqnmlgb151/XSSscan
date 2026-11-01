// Package privatefs creates sensitive artifacts with access restricted at creation.
package privatefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func randomPath(dir, prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, prefix+hex.EncodeToString(value[:])), nil
}

// TempDir creates an independent private directory; it never reuses an old path.
func TempDir(parent, prefix string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	path, err := randomPath(parent, prefix)
	if err != nil {
		return "", err
	}
	if err := createDir(path); err != nil {
		return "", err
	}
	return path, nil
}

// WriteFile replaces a regular file by same-directory rename of a new private file
// (atomic on Unix; Windows rename atomicity is not guaranteed by Go). Permission
// checks finish before writing bytes; failures never fall back to public storage.
func WriteFile(path string, data []byte) (err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if info, e := os.Lstat(abs); e == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("output must be a regular file")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	name, err := randomPath(filepath.Dir(abs), ".xsscan-private-")
	if err != nil {
		return err
	}
	file, err := createFile(name)
	if err != nil {
		return err
	}
	defer func() {
		if e := os.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove private temporary file: %w", e))
		}
	}()
	if _, e := file.Write(data); e != nil {
		return errors.Join(e, file.Close())
	}
	if e := file.Sync(); e != nil {
		return errors.Join(e, file.Close())
	}
	if e := file.Close(); e != nil {
		return e
	}
	return os.Rename(name, abs)
}
