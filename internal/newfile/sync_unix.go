//go:build !windows

package newfile

import (
	"os"
	"path/filepath"
)

// syncDir makes the new name durable.
func syncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
