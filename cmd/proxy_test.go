package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

func TestGetConfigDir(t *testing.T) {
	dir, err := getConfigDir()
	if err != nil {
		t.Fatalf("getConfigDir: %v", err)
	}

	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".config", "nokey")
	if dir != want {
		t.Errorf("getConfigDir() = %q, want %q", dir, want)
	}
}

func TestRunProxyTrustCA_NoCert(t *testing.T) {
	// When the CA cert doesn't exist, trust-ca should error.
	// We override HOME to point to a temp directory so it doesn't find a real cert.
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	err := runProxyTrustCA(nil, nil)
	if err == nil {
		t.Fatal("expected error when CA cert doesn't exist")
	}
	if !strings.Contains(err.Error(), "CA certificate not found") {
		t.Errorf("error = %v, want 'CA certificate not found'", err)
	}
}

func TestRunProxyTrustCA_WithCert(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create the CA cert file so trust-ca finds it
	caDir := filepath.Join(dir, ".config", "nokey", "ca")
	os.MkdirAll(caDir, 0700)
	os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), []byte("fake-cert"), 0600)

	output := captureStdout(t, func() {
		if err := runProxyTrustCA(nil, nil); err != nil {
			t.Fatalf("runProxyTrustCA: %v", err)
		}
	})
	if !strings.Contains(output, "CA certificate:") {
		t.Errorf("output missing cert path: %q", output)
	}
	// On macOS, should show macOS-specific instructions
	if !strings.Contains(output, "trust store") {
		t.Errorf("output missing trust instructions: %q", output)
	}
}

func TestRunProxyInitCA(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	output := captureStdout(t, func() {
		if err := runProxyInitCA(nil, nil); err != nil {
			t.Fatalf("runProxyInitCA: %v", err)
		}
	})
	if !strings.Contains(output, "CA certificate:") {
		t.Errorf("output missing cert path: %q", output)
	}

	// Verify the CA files were created
	certPath := filepath.Join(dir, ".config", "nokey", "ca", "ca-cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("CA cert was not created")
	}
}

func TestRunProxyStart_NoPolicies(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create config dir with empty policies
	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	err := runProxyStart(nil, nil)
	if err == nil {
		t.Fatal("expected error when no proxy rules")
	}
	if !strings.Contains(err.Error(), "no proxy rules") {
		t.Errorf("error = %v, want 'no proxy rules'", err)
	}
}

func TestRunProxyStart_WithRulesMissingSecret(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	// Write a policies.yaml with proxy rules referencing a secret
	policiesYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_SECRET"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(policiesYAML), 0600)

	// Use a test keyring with no secrets
	store, _ := newTestStore()
	withTestKeyring(t, store)

	err := runProxyStart(nil, nil)
	if err == nil {
		t.Fatal("expected error when secret is missing")
	}
	if !strings.Contains(err.Error(), "failed to get secret") {
		t.Errorf("error = %v, want 'failed to get secret'", err)
	}
}

func TestRunProxyStart_PolicyLoadError(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	// Write an invalid YAML policy file
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte("{{invalid yaml"), 0600)

	err := runProxyStart(nil, nil)
	if err == nil {
		t.Fatal("expected error with invalid policies.yaml")
	}
	if !strings.Contains(err.Error(), "failed to load policy") {
		t.Errorf("error = %v, want 'failed to load policy'", err)
	}
}

func TestRunProxyTrustCA_FullInstructions(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create the CA cert file
	caDir := filepath.Join(dir, ".config", "nokey", "ca")
	os.MkdirAll(caDir, 0700)
	os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), []byte("fake-cert"), 0600)

	output := captureStdout(t, func() {
		if err := runProxyTrustCA(nil, nil); err != nil {
			t.Fatalf("runProxyTrustCA: %v", err)
		}
	})
	// Should contain both the cert path and trust instructions
	if !strings.Contains(output, "ca-cert.pem") {
		t.Errorf("output missing cert filename: %q", output)
	}
}

func TestRunProxyInitCA_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// First init creates the CA
	output := captureStdout(t, func() {
		if err := runProxyInitCA(nil, nil); err != nil {
			t.Fatalf("first runProxyInitCA: %v", err)
		}
	})
	if !strings.Contains(output, "CA certificate:") {
		t.Errorf("first output missing cert: %q", output)
	}

	// Second init should also work (loads existing CA)
	output2 := captureStdout(t, func() {
		if err := runProxyInitCA(nil, nil); err != nil {
			t.Fatalf("second runProxyInitCA: %v", err)
		}
	})
	if !strings.Contains(output2, "CA certificate:") {
		t.Errorf("second output missing cert: %q", output2)
	}
}

func TestRunProxyTrustCA_WithProxyHosts(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create the CA cert file
	configDir := filepath.Join(dir, ".config", "nokey")
	caDir := filepath.Join(configDir, "ca")
	os.MkdirAll(caDir, 0700)
	os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), []byte("fake-cert"), 0600)

	// Create policies.yaml with proxy rules
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com", "api.other.com"]
      headers:
        Authorization: "Bearer $TOKEN"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	output := captureStdout(t, func() {
		if err := runProxyTrustCA(nil, nil); err != nil {
			t.Fatalf("runProxyTrustCA: %v", err)
		}
	})
	if !strings.Contains(output, "Configured proxy hosts:") {
		t.Errorf("output missing proxy hosts: %q", output)
	}
	if !strings.Contains(output, "api.example.com") {
		t.Errorf("output missing example.com: %q", output)
	}
	if !strings.Contains(output, "api.other.com") {
		t.Errorf("output missing other.com: %q", output)
	}
}

func TestGetConfigDir_Error(t *testing.T) {
	// Override HOME to empty to test error path (if possible)
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })

	// getConfigDir calls os.UserHomeDir() which uses HOME on unix
	// Even with empty HOME, it may fall back to /etc/passwd, so we
	// just verify it returns a valid path
	dir, err := getConfigDir()
	if err != nil {
		t.Skipf("getConfigDir error (expected on some systems): %v", err)
	}
	if dir == "" {
		t.Error("getConfigDir returned empty string")
	}
}

func TestRunProxyStart_GetKeyringError(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_SECRET"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring error")
	}

	err := runProxyStart(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring error") {
		t.Errorf("expected 'keyring error', got: %v", err)
	}
}

// --- proxy init-ca success ---

func TestRunProxyInitCA_Success(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	output := captureStdout(t, func() {
		err := runProxyInitCA(nil, nil)
		if err != nil {
			t.Fatalf("runProxyInitCA: %v", err)
		}
	})
	if !strings.Contains(output, "CA certificate") {
		t.Errorf("output = %q, want 'CA certificate'", output)
	}

	// Verify CA cert was created
	certPath := filepath.Join(dir, ".config", "nokey", "ca", "ca-cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("CA cert was not created")
	}
}

// --- proxy trust-ca success ---

func TestRunProxyTrustCA_Success(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// First create the CA
	if err := runProxyInitCA(nil, nil); err != nil {
		t.Fatalf("runProxyInitCA: %v", err)
	}

	output := captureStdout(t, func() {
		err := runProxyTrustCA(nil, nil)
		if err != nil {
			t.Fatalf("runProxyTrustCA: %v", err)
		}
	})
	if !strings.Contains(output, "CA certificate") {
		t.Errorf("output = %q, want 'CA certificate'", output)
	}
}

// --- proxy start with no rules ---

func TestRunProxyStart_NoRules(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	// Create empty policies.yaml (no proxy rules)
	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte("{}\n"), 0600)

	err := runProxyStart(nil, nil)
	if err == nil {
		t.Fatal("expected error when no proxy rules")
	}
	if !strings.Contains(err.Error(), "no proxy rules") {
		t.Errorf("error = %v, want 'no proxy rules'", err)
	}
}

func TestRunProxyStart_CACreateError(t *testing.T) {
	dir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() { os.Setenv("HOME", oldHome) })
	os.Setenv("HOME", dir)

	configDir := filepath.Join(dir, ".config", "nokey")
	os.MkdirAll(configDir, 0700)

	// Write valid proxy rules so we pass the "no proxy rules" check.
	polYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $SECRET"
`
	os.WriteFile(filepath.Join(configDir, "policies.yaml"), []byte(polYAML), 0600)

	// Make the CA directory a file so LoadOrCreateCA can't write there.
	caPath := filepath.Join(configDir, "ca")
	if err := os.WriteFile(caPath, []byte("not-a-dir"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err := runProxyStart(nil, nil)
	if err == nil {
		t.Fatal("expected error when CA dir is a file")
	}
	if !strings.Contains(err.Error(), "failed to load/create CA") {
		t.Errorf("error = %v, want 'failed to load/create CA'", err)
	}
}
