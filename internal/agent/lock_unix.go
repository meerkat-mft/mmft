//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// keyStorageSupported reports whether private keys can be stored safely here.
const keyStorageSupported = true

const lockRetry = 50 * time.Millisecond

// lock takes an exclusive lock on the agent directory, so that two installs
// can't interleave. It gives up when ctx ends, so a stalled install can't hold
// up another past its deadline. The operating system releases the lock if the
// process dies.
func lock(ctx context.Context, dir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(filepath.Clean(dir), lockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd()) //nolint:gosec // a file descriptor always fits in an int
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockRetry):
		}
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
