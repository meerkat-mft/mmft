//go:build windows

package trust

import "os"

// File modes don't protect files on Windows, and access control lists aren't
// checked yet, so nothing can show that a key or passphrase file is private.
// Every private file and key directory is refused until those checks exist,
// which the Windows agent work in #3 will add.
func checkPrivateFile(os.FileInfo) error { return ErrUnsupportedPlatform }

func checkPrivateDir(os.FileInfo) error { return ErrUnsupportedPlatform }

func syncDir(string) error { return nil }
