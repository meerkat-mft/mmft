// Package newfile creates files that must never replace an existing one, such
// as keys. A reader sees either no file or the whole file, never part of one.
package newfile

import (
	"os"
	"path/filepath"
)

// Write creates path holding data with mode. It fails with an error matching
// fs.ErrExist if path already exists, and then leaves it untouched. The data is
// written and synced under a temporary name, then linked into place, so a
// concurrent reader or a crash can't leave a partial file at path.
func Write(path string, data []byte, mode os.FileMode) (err error) {
	path = filepath.Clean(path)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// A hard link fails if path exists, unlike a rename, which would replace it.
	if err := os.Link(tmp.Name(), path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}
