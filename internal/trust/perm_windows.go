//go:build windows

package trust

import "os"

// Windows access control lists aren't checked yet, so these guards don't apply
// there. That must be closed before administrators use the CLI on Windows.
func checkPrivateFile(os.FileInfo) error { return nil }

func checkPrivateDir(os.FileInfo) error { return nil }

func syncDir(string) error { return nil }
