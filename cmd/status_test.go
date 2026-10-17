package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/version"
)

func TestRunStatus_NoSecrets(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !strings.Contains(output, "nokey status:") {
		t.Error("output should contain header")
	}
	if !strings.Contains(output, "not configured") {
		t.Error("output should show PIN not configured")
	}
	if !strings.Contains(output, "Secrets stored:") {
		t.Error("output should show secrets count")
	}
}

func TestRunStatus_JSON(t *testing.T) {
	store, _ := newTestStore()
	store.Set("KEY1", "val")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := statusJSON
	t.Cleanup(func() { statusJSON = old })
	statusJSON = true

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})
	if !strings.Contains(output, `"keyring"`) {
		t.Errorf("JSON output should contain keyring: %q", output)
	}
	if !strings.Contains(output, `"secrets": 1`) {
		t.Errorf("JSON output should contain secrets count: %q", output)
	}
}

func TestRunStatus_WithPIN(t *testing.T) {
	store, _ := newTestStore()
	_ = store.SetPINHash("somehash")
	_ = store.Set("MY_KEY", "val")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !strings.Contains(output, "configured") {
		t.Error("output should show PIN configured")
	}
	if !strings.Contains(output, "1") {
		t.Error("output should show 1 secret")
	}
}

// writeTestConfigFile writes config.yaml into the isolated test config dir.
func writeTestConfigFile(t *testing.T, content string) {
	t.Helper()
	path, err := config.ConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func runStatusJSON(t *testing.T) map[string]any {
	t.Helper()
	old := statusJSON
	t.Cleanup(func() { statusJSON = old })
	statusJSON = true

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})
	var got map[string]any
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", output, err)
	}
	return got
}

func TestRunStatus_InvalidConfigReported(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	writeTestConfigFile(t, "audti:\n  enabled: true\n")

	got := runStatusJSON(t)
	if s, _ := got["config"].(string); !strings.HasPrefix(s, "error:") {
		t.Errorf("config = %q, want an error for an unknown key", got["config"])
	}
}

func TestRunStatus_NewFields(t *testing.T) {
	store, _ := newTestStore()
	_ = store.SetPINHash("somehash")
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	dir, _ := config.ConfigDir()
	if err := os.MkdirAll(filepath.Join(dir, "ca"), 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ca", "ca-cert.pem"), []byte("x"), 0600)

	got := runStatusJSON(t)
	for _, k := range []string{"keyring", "pin", "config", "policy", "policy_rules", "proxy_rules", "secrets"} {
		if _, ok := got[k]; !ok {
			t.Errorf("existing field %q missing", k)
		}
	}
	if got["config"] != "valid" {
		t.Errorf("config = %v, want valid", got["config"])
	}
	if got["audit_enabled"] != true {
		t.Errorf("audit_enabled = %v, want true", got["audit_enabled"])
	}
	if got["auth_method"] != "pin" {
		t.Errorf("auth_method = %v, want pin", got["auth_method"])
	}
	if got["config_dir"] != dir {
		t.Errorf("config_dir = %v, want %s", got["config_dir"], dir)
	}
	if got["ca_present"] != true {
		t.Errorf("ca_present = %v, want true", got["ca_present"])
	}
	if got["version"] != version.Version {
		t.Errorf("version = %v, want %s", got["version"], version.Version)
	}
}

func TestRunStatus_AuthMethodFromConfig(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Auth.DefaultMethod = "oauth"
	withTestConfig(t, c)

	got := runStatusJSON(t)
	if got["auth_method"] != "oauth" {
		t.Errorf("auth_method = %v, want oauth", got["auth_method"])
	}
	if got["ca_present"] != false {
		t.Errorf("ca_present = %v, want false", got["ca_present"])
	}
}

func TestRunDoctor_Healthy(t *testing.T) {
	store, _ := newTestStore()
	_ = store.SetPINHash("somehash")
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	var err error
	output := captureStdout(t, func() { err = runDoctor(nil, nil) })
	if err != nil {
		t.Fatalf("runDoctor: %v\n%s", err, output)
	}
	if strings.Contains(output, "FAIL") {
		t.Errorf("healthy setup reported a failure:\n%s", output)
	}
}

func TestRunDoctor_InvalidConfigFails(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	writeTestConfigFile(t, "audti:\n  enabled: true\n")

	var err error
	output := captureStdout(t, func() { err = runDoctor(nil, nil) })
	if err == nil {
		t.Fatal("runDoctor should fail on an invalid config")
	}
	if !strings.Contains(output, "FAIL") || !strings.Contains(output, "nokey config validate") {
		t.Errorf("output should show the failure and a fix-it hint:\n%s", output)
	}
}

func TestRunDoctor_InvalidPolicyFails(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())
	dir, _ := config.ConfigDir()
	os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte("rulez: []\n"), 0600)

	var err error
	output := captureStdout(t, func() { err = runDoctor(nil, nil) })
	if err == nil {
		t.Fatalf("runDoctor should fail on an invalid policy:\n%s", output)
	}
	if !strings.Contains(output, "policies.yaml") {
		t.Errorf("output should name the policy file:\n%s", output)
	}
}

func TestRunDoctor_KeyringErrorFails(t *testing.T) {
	withTestConfig(t, config.DefaultConfig())
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) { return nil, errors.New("no backend") }

	var err error
	output := captureStdout(t, func() { err = runDoctor(nil, nil) })
	if err == nil {
		t.Fatal("runDoctor should fail when the keyring cannot be opened")
	}
	if !strings.Contains(output, "no backend") {
		t.Errorf("output should include the keyring error:\n%s", output)
	}
}

func TestRunDoctor_WarningsDoNotFail(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig()) // no PIN, audit disabled

	var err error
	output := captureStdout(t, func() { err = runDoctor(nil, nil) })
	if err != nil {
		t.Fatalf("warnings alone should not fail doctor: %v\n%s", err, output)
	}
	if !strings.Contains(output, "WARN") || !strings.Contains(output, "nokey auth setup") {
		t.Errorf("output should warn about the missing PIN with a hint:\n%s", output)
	}
}
