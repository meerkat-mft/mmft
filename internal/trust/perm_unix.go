//go:build !windows

package trust

import (
	"os"
	"path/filepath"
	"syscall"
)

func ownedByUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// checkPrivateFile requires a file with no group or other access, owned by this
// user.
func checkPrivateFile(info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 || !ownedByUser(info) {
		return ErrNotPrivate
	}
	return nil
}

// checkPrivateDir requires a directory that only this user can change.
func checkPrivateDir(info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 || !ownedByUser(info) {
		return ErrNotPrivate
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
