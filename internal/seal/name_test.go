package seal

import (
	"strings"
	"testing"
)

func TestValidFileName(t *testing.T) {
	for _, name := range []string{"report.csv", "a", ".hidden", "naïve résumé.txt", "x..y", strings.Repeat("a", MaxFileNameBytes),
		"console.txt", "com10", "nullable", "my con.txt"} {
		if !ValidFileName(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{
		"", ".", "..", "a/b", "../x", "/etc/passwd", `a\b`, `..\x`, "a\x00b", "a\nb", "a\tb", "\x7f",
		strings.Repeat("a", MaxFileNameBytes+1), "\xff\xfe",
		"a:b", "report.csv:hidden", "trailing.", "trailing ", "CON", "con.txt", "Nul", "COM1.log", "lpt9", "aux .txt",
	} {
		if ValidFileName(name) {
			t.Errorf("%q accepted", name)
		}
	}
}
