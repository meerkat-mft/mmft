package trust

import "testing"

// SetScryptWorkFactorForTests lowers the cost of wrapping and unwrapping key
// files so tests outside this package, such as the CLI's, don't pay the
// production cost on every key. It panics outside a test binary, so a release
// can never weaken a key file.
func SetScryptWorkFactorForTests(logN int) {
	if !testing.Testing() {
		panic("trust: SetScryptWorkFactorForTests called outside a test")
	}
	scryptWorkFactor = logN
}
