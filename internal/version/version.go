// Package version holds the release version shared by all Meerkat MFT components.
package version

import "fmt"

// Version is set at build time with -ldflags.
var Version = "dev"

// String returns the name of a component with its version.
func String(component string) string {
	return fmt.Sprintf("%s %s", component, Version)
}
