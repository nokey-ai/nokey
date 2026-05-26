//go:build darwin

package keyring

import (
	"bytes"
	"fmt"
	"os/exec"
)

// ApplyKeychainSettings configures a macOS keychain's lock policy so it
// auto-locks on sleep and after a 5 minute idle timeout. Idempotent —
// invoking on an existing keychain re-applies the settings.
//
// The flags map to `security set-keychain-settings`:
//
//	-l       lock when the system sleeps
//	-u       lock after the idle timeout
//	-t 300   idle timeout in seconds (5 minutes)
//
// Stderr from the security tool is captured into the returned error so
// callers can see why the command failed (e.g. missing keychain path).
func ApplyKeychainSettings(keychainPath string) error {
	cmd := exec.Command("/usr/bin/security", "set-keychain-settings", "-l", "-u", "-t", "300", keychainPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security set-keychain-settings %s: %w (stderr: %s)", keychainPath, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return nil
}
