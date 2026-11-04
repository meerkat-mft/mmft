//go:build windows

package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const pass = "correct horse battery staple"

// Until access control lists are checked, Windows refuses every private file
// and key directory rather than trusting them blindly.
func TestWindowsRefusesPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := InitRoot(filepath.Join(dir, "root"), pass); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("trust init: %v", err)
	}
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPassphrase(passFile); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("passphrase file: %v", err)
	}
}
