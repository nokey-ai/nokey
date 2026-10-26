//go:build darwin

package keyring

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeychainUnlocked(t *testing.T) {
	if _, err := os.Stat("/usr/bin/security"); err != nil {
		t.Skip("/usr/bin/security not available")
	}
	dir := filepath.Join(t.TempDir(), "Library", "Keychains")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "status.keychain-db")
	security := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("/usr/bin/security", args...).CombinedOutput(); err != nil {
			t.Skipf("security %s: %v (%s)", args[0], err, strings.TrimSpace(string(out)))
		}
	}

	if KeychainUnlocked(path) {
		t.Error("KeychainUnlocked = true for a keychain that doesn't exist")
	}
	security("create-keychain", "-p", "testpw", path)
	t.Cleanup(func() { _ = exec.Command("/usr/bin/security", "delete-keychain", path).Run() })
	security("unlock-keychain", "-p", "testpw", path)
	if !KeychainUnlocked(path) {
		t.Error("KeychainUnlocked = false for an unlocked keychain")
	}
	security("lock-keychain", path)
	if KeychainUnlocked(path) {
		t.Error("KeychainUnlocked = true for a locked keychain")
	}
}
