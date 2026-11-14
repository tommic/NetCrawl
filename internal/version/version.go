// Package version holds the build version, set at build time with
//
//	go build -ldflags "-X netcrawler/internal/version.Version=v0.2.0"
package version

// Version is the build version ("dev" for local builds).
var Version = "dev"
