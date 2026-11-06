package seal

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxFileNameBytes is the longest file name a manual delivery accepts, the
// common limit of file systems.
const MaxFileNameBytes = 255

// windowsDevices are names Windows reads as devices, with any extension.
var windowsDevices = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// ValidFileName reports whether name is a bare file name that can only ever
// mean one file directly inside a directory, on Linux, macOS, and Windows
// alike: 1 to 255 bytes of valid UTF-8, with no path separator, colon, NUL,
// or control character, not "." or "..", not ending in a dot or space, and not
// a Windows device name. Manual deliveries use it on both agents and in the
// API. See ADR 0021.
func ValidFileName(name string) bool {
	if name == "" || len(name) > MaxFileNameBytes || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	// A colon names an alternate data stream on Windows.
	if strings.ContainsAny(name, `/\:`) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	base, _, _ := strings.Cut(name, ".")
	if windowsDevices[strings.ToLower(strings.TrimRight(base, " "))] {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
