package newfile

// syncDir does nothing on Windows, where directories can't be synced.
func syncDir(string) error { return nil }
