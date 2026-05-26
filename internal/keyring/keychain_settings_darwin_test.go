//go:build darwin

package keyring

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestApplyKeychainSettings creates a throwaway keychain, applies the
// nokey lock-policy settings, and parses `security show-keychain-info`
// output to confirm the timeout and lock-on-sleep flag are set. Skips
// gracefully if /usr/bin/security is missing or keychain creation fails
// (e.g. CI environments without sudo/keychain access).
func TestApplyKeychainSettings(t *testing.T) {
	if _, err := os.Stat("/usr/bin/security"); err != nil {
		t.Skip("/usr/bin/security not available")
	}

	tmpDir := t.TempDir()
	kcPath := filepath.Join(tmpDir, fmt.Sprintf("nokey-test-%d.keychain", os.Getpid()))

	// Use -p to provide the password non-interactively. If create-keychain
	// still prompts (sandboxed CI etc.), skip rather than fail.
	createCmd := exec.Command("/usr/bin/security", "create-keychain", "-p", "testpw", kcPath)
	var createErr bytes.Buffer
	createCmd.Stderr = &createErr
	if err := createCmd.Run(); err != nil {
		t.Skipf("could not create test keychain (%v): %s", err, createErr.String())
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-keychain", kcPath).Run()
	})

	if err := ApplyKeychainSettings(kcPath); err != nil {
		t.Fatalf("ApplyKeychainSettings: %v", err)
	}

	// Re-apply to prove idempotency.
	if err := ApplyKeychainSettings(kcPath); err != nil {
		t.Fatalf("ApplyKeychainSettings (second call) should be idempotent: %v", err)
	}

	infoCmd := exec.Command("/usr/bin/security", "show-keychain-info", kcPath)
	var infoOut bytes.Buffer
	infoCmd.Stdout = &infoOut
	infoCmd.Stderr = &infoOut
	if err := infoCmd.Run(); err != nil {
		t.Fatalf("show-keychain-info: %v: %s", err, infoOut.String())
	}

	out := infoOut.String()
	// security writes timeout as something like "Keychain "<path>" timeout=300s"
	if !strings.Contains(out, "timeout=300") {
		t.Errorf("show-keychain-info output missing timeout=300; got:\n%s", out)
	}
	// lock-on-sleep is reported as "lock-on-sleep" when -l is set.
	if !strings.Contains(out, "lock-on-sleep") {
		t.Errorf("show-keychain-info output missing lock-on-sleep; got:\n%s", out)
	}
}
