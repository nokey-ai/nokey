package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func runConfigValidateJSON(t *testing.T) (map[string]map[string]any, error) {
	t.Helper()
	old := configValidateJSON
	t.Cleanup(func() { configValidateJSON = old })
	configValidateJSON = true

	var err error
	output := captureStdout(t, func() { err = runConfigValidate(nil, nil) })
	var got map[string]map[string]any
	if jerr := json.Unmarshal([]byte(output), &got); jerr != nil {
		t.Fatalf("invalid JSON %q: %v", output, jerr)
	}
	return got, err
}

func TestRunConfigValidate_JSONValid(t *testing.T) {
	withTestConfig(t, config.DefaultConfig())

	got, err := runConfigValidateJSON(t)
	if err != nil {
		t.Fatalf("runConfigValidate: %v", err)
	}
	if got["config"]["valid"] != true {
		t.Errorf("config = %v, want valid", got["config"])
	}
	if got["policy"]["valid"] != true || got["policy"]["found"] != false {
		t.Errorf("policy = %v, want valid and not found", got["policy"])
	}
}

func TestRunConfigValidate_JSONReportsBothErrors(t *testing.T) {
	withTestConfig(t, config.DefaultConfig())
	dir, _ := config.ConfigDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("audti: {}\n"), 0600)
	os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte("rulez: []\n"), 0600)

	got, err := runConfigValidateJSON(t)
	if err == nil {
		t.Fatal("runConfigValidate should fail on invalid files")
	}
	for _, k := range []string{"config", "policy"} {
		if got[k]["valid"] != false {
			t.Errorf("%s = %v, want invalid", k, got[k])
		}
		if s, _ := got[k]["error"].(string); s == "" {
			t.Errorf("%s should carry an error message: %v", k, got[k])
		}
	}
}
