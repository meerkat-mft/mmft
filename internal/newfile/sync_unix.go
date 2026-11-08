//go:build !windows

package newfile

import (
	"os"
	"path/filepath"
)

// SyncDir makes the new name durable.
func SyncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// SyncRoot is SyncDir for a directory opened as a root.
func SyncRoot(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
