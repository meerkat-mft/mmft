package newfile

// SyncDir does nothing on Windows, where directories can't be synced.
func SyncDir(string) error { return nil }
