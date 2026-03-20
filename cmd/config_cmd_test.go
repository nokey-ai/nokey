package cmd

import (
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
)

func TestRunConfigValidate_DefaultConfig(t *testing.T) {
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runConfigValidate(nil, nil); err != nil {
			t.Fatalf("runConfigValidate: %v", err)
		}
	})

	if !strings.Contains(output, "config.yaml: OK") {
		t.Errorf("output should contain 'config.yaml: OK', got: %s", output)
	}
}
