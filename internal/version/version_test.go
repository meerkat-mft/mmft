package version

import "testing"

func TestString(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "0.1.0"

	got := String("mmft-agent")
	if want := "mmft-agent 0.1.0"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
