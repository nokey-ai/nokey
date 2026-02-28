package version

import "testing"

func TestVersionDefault(t *testing.T) {
	// When not set via -ldflags at build time, Version defaults to "dev".
	if Version == "" {
		t.Error("Version should not be empty string")
	}
}
