package newfile

import "os"

// SyncDir does nothing on Windows, where directories can't be synced.
func SyncDir(string) error { return nil }

// SyncRoot does nothing on Windows, where directories can't be synced.
func SyncRoot(*os.Root) error { return nil }
