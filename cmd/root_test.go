package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
)

func TestInitConfig_Defaults(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })

	// initConfig should produce a non-nil cfg even without a config file.
	initConfig()
	if cfg == nil {
		t.Fatal("initConfig() should set cfg")
	}
}

func TestInitConfig_EnvOverride(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })

	oldEnv := os.Getenv("NOKEY_BACKEND")
	t.Cleanup(func() { os.Setenv("NOKEY_BACKEND", oldEnv) })
	os.Setenv("NOKEY_BACKEND", "test-backend")

	initConfig()

	if cfg.DefaultBackend != "test-backend" {
		t.Errorf("DefaultBackend = %q, want %q", cfg.DefaultBackend, "test-backend")
	}
}

func TestInitConfig_FlagOverridesEnv(t *testing.T) {
	old := cfg
	oldBackend := backend
	t.Cleanup(func() {
		cfg = old
		backend = oldBackend
	})

	oldEnv := os.Getenv("NOKEY_BACKEND")
	t.Cleanup(func() { os.Setenv("NOKEY_BACKEND", oldEnv) })
	os.Setenv("NOKEY_BACKEND", "env-backend")

	backend = "flag-backend"
	initConfig()

	if cfg.DefaultBackend != "flag-backend" {
		t.Errorf("DefaultBackend = %q, want %q", cfg.DefaultBackend, "flag-backend")
	}
}

func TestVersionCmd(t *testing.T) {
	output := captureStdout(t, func() {
		versionCmd.Run(versionCmd, nil)
	})
	if !strings.Contains(output, "nokey") {
		t.Errorf("version output = %q, expected to contain 'nokey'", output)
	}
}

func TestGetKeyring_DefaultReturnsNonNil(t *testing.T) {
	// With a valid config, getKeyring should at least not panic.
	// It may fail on CI without a real keyring, so we just ensure our
	// overridable function var works.
	c := config.DefaultConfig()
	withTestConfig(t, c)

	store, _ := newTestStore()
	withTestKeyring(t, store)

	got, err := getKeyring()
	if err != nil {
		t.Fatalf("getKeyring() error: %v", err)
	}
	if got == nil {
		t.Fatal("getKeyring() returned nil store")
	}
}

func TestInitConfig_LoadError(t *testing.T) {
	old := cfg
	t.Cleanup(func() { cfg = old })

	// Point HOME to a temp dir with a malformed config.yaml
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create config dir with invalid YAML
	configDir := dir + "/.config/nokey"
	os.MkdirAll(configDir, 0700)
	os.WriteFile(configDir+"/config.yaml", []byte("{{invalid yaml"), 0600)

	stderr := captureStderr(t, func() {
		initConfig()
	})

	// Should fall back to defaults
	if cfg == nil {
		t.Fatal("initConfig should set cfg even on load error")
	}
	// Should print a warning
	if !strings.Contains(stderr, "Warning") {
		t.Errorf("stderr = %q, want warning about config load", stderr)
	}
}
