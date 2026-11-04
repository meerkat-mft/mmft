//go:build windows

package agent

// keyStorageSupported is false until the agent can set and check a private
// access control list, because file modes don't protect files on Windows.
// The Windows agent is still being designed.
const keyStorageSupported = false

func lock(string) (func(), error) {
	return nil, ErrUnsupported
}
