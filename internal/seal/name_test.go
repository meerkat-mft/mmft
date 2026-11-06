package seal

import (
	"strings"
	"testing"
)

func TestValidFileName(t *testing.T) {
	for _, name := range []string{"report.csv", "a", ".hidden", "naïve résumé.txt", "x..y", strings.Repeat("a", MaxFileNameBytes)} {
		if !ValidFileName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{
		"", ".", "..", "a/b", "../x", "/etc/passwd", `a\b`, `..\x`, "a\x00b", "a\nb", "a\tb", "\x7f",
		strings.Repeat("a", MaxFileNameBytes+1), "\xff\xfe",
	} {
		if ValidFileName(name) {
			t.Errorf("%q accepted", name)
		}
	}
}
