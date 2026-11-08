//go:build windows

package allowlist

// Load denies everything on Windows until the Windows agent is defined (#3).
func Load(string) (*Allowlist, error) {
	return Parse(nil)
}
