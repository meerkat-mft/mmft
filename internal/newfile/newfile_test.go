package newfile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestWriteCreatesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := Write(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "secret" {
		t.Fatalf("got %q, %v", got, err)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

func TestWriteNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want fs.ErrExist", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "first" {
		t.Fatalf("the file was replaced: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

// Readers racing the writers see no file or a whole one, never part of one.
func TestConcurrentWritersAndReaders(t *testing.T) {
	data := bytes.Repeat([]byte("k"), 64<<10)
	for range 20 {
		path := filepath.Join(t.TempDir(), "key")
		var wg sync.WaitGroup
		wins := make(chan struct{}, 16)
		for range 8 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if Write(path, data, 0o600) == nil {
					wins <- struct{}{}
				}
			}()
			go func() {
				defer wg.Done()
				if got, err := os.ReadFile(path); err == nil && !bytes.Equal(got, data) {
					t.Errorf("read %d of %d bytes", len(got), len(data))
				}
			}()
		}
		wg.Wait()
		close(wins)
		if n := len(wins); n != 1 {
			t.Fatalf("%d writers won, want 1", n)
		}
	}
}
