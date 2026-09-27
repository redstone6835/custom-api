// Package version carries build identity for all customs binaries.
package version

import (
	"fmt"
	"runtime"
)

// These are overridden at build time with -ldflags "-X ...".
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// String renders a one-line build identity.
func String() string {
	return fmt.Sprintf("customapi %s (commit %s, built %s, %s/%s, %s)",
		Version, Commit, BuildTime, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
