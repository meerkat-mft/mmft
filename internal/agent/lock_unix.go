//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"syscall"
)

// keyStorageSupported reports whether private keys can be stored safely here.
const keyStorageSupported = true

// lock takes an exclusive lock on the agent directory, so that two installs
// can't interleave. The operating system releases it if the process dies.
func lock(dir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(filepath.Clean(dir), lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd()) //nolint:gosec // a file descriptor always fits in an int
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
