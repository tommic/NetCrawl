// Package version holds the build version.
//
// The version is kept in the file VERSION next to this file (semantic
// versioning, see CHANGELOG.md) and compiled in. A build can still
// override it, e.g. with a commit id:
//
//	go build -ldflags "-X netcrawler/internal/version.Version=0.6.0+abc1234"
package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var file string

// Version is the build version, e.g. "0.6.0".
var Version string

func init() {
	if Version == "" {
		Version = strings.TrimSpace(file)
	}
}
