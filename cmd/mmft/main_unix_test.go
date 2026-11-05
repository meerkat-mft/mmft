//go:build !windows

package main

import (
	"os"
	"testing"

	"mmft.dev/mmft/internal/trust"
)

// TestMain lowers the scrypt cost of the key files these tests create. At the
// production cost, each `trust init`, `admin init`, and `certify-admin` takes
// seconds under the race detector, and the suite took over four minutes.
// internal/trust keeps the test that pins the production work factor.
func TestMain(m *testing.M) {
	trust.SetScryptWorkFactorForTests(10)
	os.Exit(m.Run())
}
