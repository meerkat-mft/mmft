package seal

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxFileNameBytes is the longest file name a manual delivery accepts, the
// common limit of file systems.
const MaxFileNameBytes = 255

// ValidFileName reports whether name is a bare file name that can only ever
// mean one file directly inside a directory: 1 to 255 bytes of valid UTF-8,
// with no path separator, NUL, or control character, and not "." or "..".
// Manual deliveries use it on both agents and in the API. See ADR 0021.
func ValidFileName(name string) bool {
	if name == "" || len(name) > MaxFileNameBytes || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
