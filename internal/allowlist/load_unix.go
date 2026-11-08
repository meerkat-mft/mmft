//go:build unix

package allowlist

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// protected decides whether the allowlist file and the directories above it
// are safe from everyone but root. Tests replace it, because they can't
// create files owned by root.
var protected = rootOnly

// Load reads the allowlist file at path. A missing file gives an allowlist
// that denies everything. The file is opened without following a link, and
// its bytes are read and hashed from that one open file. It fails with
// ErrUnprotected unless the file and every directory above it are owned by
// root and writable by no group or other user, and the agent isn't root.
func Load(path string) (*Allowlist, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: the allowlist path must be absolute", ErrInvalid)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if errors.Is(err, fs.ErrNotExist) {
		return Parse(nil)
	}
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- the host sets this path, and the file is checked below.
	f, err := os.OpenFile(filepath.Join(dir, filepath.Base(path)), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Parse(nil)
	case errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("%w: the allowlist file is a link", ErrUnprotected)
	case err != nil:
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: the allowlist is not a regular file", ErrUnprotected)
	}
	chain := []fs.FileInfo{info}
	for d := dir; ; d = filepath.Dir(d) {
		di, err := os.Lstat(d)
		if err != nil {
			return nil, err
		}
		chain = append(chain, di)
		if d == filepath.Dir(d) {
			break
		}
	}
	if err := protected(chain, os.Geteuid()); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// rootOnly requires the agent not to run as root, which could write the file,
// and the file and each directory above it to be owned by root and not
// writable by group or others. A writable directory would let the file be
// replaced.
func rootOnly(chain []fs.FileInfo, euid int) error {
	if euid == 0 {
		return fmt.Errorf("%w: the agent is running as root", ErrUnprotected)
	}
	for _, fi := range chain {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrUnprotected
		}
		if st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return ErrUnprotected
		}
	}
	return nil
}
