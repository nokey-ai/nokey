package cmd

import (
	"fmt"
	"strings"
	"testing"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// --- PIN auth ---

func TestRunAuthSetup_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	// Mock SetupPIN to return a fake hash
	old := authSetupPINFn
	t.Cleanup(func() { authSetupPINFn = old })
	authSetupPINFn = func() (string, error) {
		return "fake-hash-value", nil
	}

	output := captureStdout(t, func() {
		if err := runAuthSetup(nil, nil); err != nil {
			t.Fatalf("runAuthSetup: %v", err)
		}
	})
	if !strings.Contains(output, "PIN authentication enabled") {
		t.Errorf("output = %q, want success message", output)
	}

	// Verify hash was stored
	if !store.HasPIN() {
		t.Error("store should have PIN after setup")
	}
}

func TestRunAuthSetup_AlreadyConfigured(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	// Pre-set a PIN hash
	store.SetPINHash("existing-hash")

	err := runAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "PIN already configured") {
		t.Errorf("expected 'PIN already configured' error, got: %v", err)
	}
}

func TestRunAuthChange_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("old-hash")

	old := authChangePINFn
	t.Cleanup(func() { authChangePINFn = old })
	authChangePINFn = func(oldHash string) (string, error) {
		if oldHash != "old-hash" {
			t.Errorf("changePIN received wrong old hash: %q", oldHash)
		}
		return "new-hash", nil
	}

	output := captureStdout(t, func() {
		if err := runAuthChange(nil, nil); err != nil {
			t.Fatalf("runAuthChange: %v", err)
		}
	})
	if !strings.Contains(output, "PIN changed successfully") {
		t.Errorf("output = %q, want success message", output)
	}

	hash, _ := store.GetPINHash()
	if hash != "new-hash" {
		t.Errorf("stored hash = %q, want %q", hash, "new-hash")
	}
}

func TestRunAuthDisable_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("my-hash")

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		if storedHash != "my-hash" {
			t.Errorf("authenticate received wrong hash: %q", storedHash)
		}
		return nil
	}

	output := captureStdout(t, func() {
		if err := runAuthDisable(nil, nil); err != nil {
			t.Fatalf("runAuthDisable: %v", err)
		}
	})
	if !strings.Contains(output, "PIN authentication disabled") {
		t.Errorf("output = %q, want success message", output)
	}

	if store.HasPIN() {
		t.Error("store should not have PIN after disable")
	}
}

func TestRunAuthStatus_Enabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("some-hash")

	output := captureStdout(t, func() {
		if err := runAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "ENABLED") {
		t.Errorf("output = %q, want ENABLED", output)
	}
}

func TestRunAuthStatus_Disabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "DISABLED") {
		t.Errorf("output = %q, want DISABLED", output)
	}
}

func TestRunAuthChange_NoPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	err := runAuthChange(nil, nil)
	if err == nil {
		t.Fatal("expected error when no PIN configured")
	}
}

func TestRunAuthDisable_NoPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	err := runAuthDisable(nil, nil)
	if err == nil {
		t.Fatal("expected error when no PIN configured")
	}
}

func TestRunAuthSetup_SetupPINError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authSetupPINFn
	t.Cleanup(func() { authSetupPINFn = old })
	authSetupPINFn = func() (string, error) {
		return "", fmt.Errorf("pin entry failed")
	}

	err := runAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "pin entry failed") {
		t.Errorf("expected 'pin entry failed' error, got: %v", err)
	}
}

func TestRunAuthChange_ChangePINError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("old-hash")

	old := authChangePINFn
	t.Cleanup(func() { authChangePINFn = old })
	authChangePINFn = func(oldHash string) (string, error) {
		return "", fmt.Errorf("wrong pin")
	}

	err := runAuthChange(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "wrong pin") {
		t.Errorf("expected 'wrong pin' error, got: %v", err)
	}
}

func TestRunAuthDisable_AuthFailed(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("my-hash")

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		return fmt.Errorf("auth failed")
	}

	err := runAuthDisable(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("expected 'auth failed' error, got: %v", err)
	}
}

func TestRunAuthStatus_WithSession(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	store.SetPINHash("some-hash")

	output := captureStdout(t, func() {
		if err := runAuthStatus(nil, nil); err != nil {
			t.Fatalf("runAuthStatus: %v", err)
		}
	})
	if !strings.Contains(output, "ENABLED") {
		t.Errorf("output = %q, want ENABLED", output)
	}
}

func TestRunAuthSetup_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthSetup(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthChange_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthChange(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthDisable_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthDisable(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuthStatus_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	withTestConfig(t, config.DefaultConfig())

	err := runAuthStatus(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

// --- auth setup/change/disable SetPINHash/DeletePINHash errors ---

func TestRunAuthSetup_SetPINHashError(t *testing.T) {
	// Use errorSetRing so SetPINHash (which calls ring.Set) fails
	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authSetupPINFn
	t.Cleanup(func() { authSetupPINFn = old })
	authSetupPINFn = func() (string, error) {
		return "new-hash", nil
	}

	err := runAuthSetup(nil, nil)
	if err == nil {
		t.Fatal("expected error when SetPINHash fails")
	}
	if !strings.Contains(err.Error(), "set failed") {
		t.Errorf("error = %v, want 'set failed'", err)
	}
}

func TestRunAuthChange_SetPINHashError(t *testing.T) {
	// Pre-store PIN hash directly in mockRing, then wrap with errorSetRing
	ring := newMockRing()
	ring.items["__nokey_pin_hash__"] = kring.Item{
		Key:  "__nokey_pin_hash__",
		Data: []byte("old-hash"),
	}
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authChangePINFn
	t.Cleanup(func() { authChangePINFn = old })
	authChangePINFn = func(oldHash string) (string, error) {
		return "new-hash", nil
	}

	err := runAuthChange(nil, nil)
	if err == nil {
		t.Fatal("expected error when SetPINHash fails")
	}
	if !strings.Contains(err.Error(), "set failed") {
		t.Errorf("error = %v, want 'set failed'", err)
	}
}

func TestRunAuthDisable_DeletePINHashError(t *testing.T) {
	// Pre-store PIN hash, then wrap with errorRemoveRing
	ring := newMockRing()
	ring.items["__nokey_pin_hash__"] = kring.Item{
		Key:  "__nokey_pin_hash__",
		Data: []byte("my-hash"),
	}
	store := nkeyring.NewWithRing(&errorRemoveRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error { return nil }

	err := runAuthDisable(nil, nil)
	if err == nil {
		t.Fatal("expected error when DeletePINHash fails")
	}
	if !strings.Contains(err.Error(), "remove failed") {
		t.Errorf("error = %v, want 'remove failed'", err)
	}
}
