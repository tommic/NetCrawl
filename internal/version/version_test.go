package version

import (
	"regexp"
	"testing"
)

func TestVersionFile(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(file[:len(file)-1]) || file[len(file)-1] != '\n' {
		t.Errorf("VERSION = %q, want MAJOR.MINOR.PATCH and a newline", file)
	}
	if Version == "" {
		t.Error("Version is empty")
	}
}
