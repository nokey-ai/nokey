//go:build darwin

package keyring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// securityItemNotFound is the exit status `security find-generic-password`
// uses when no item matches.
const securityItemNotFound = 44

// FindStaleTouchIDItem reports a Touch ID item in the login keychain that
// belongs to a different dedicated keychain than keychainName, or nil if
// there is none. It reads only the item's attributes, never its data, so it
// doesn't trigger a keychain access prompt.
func FindStaleTouchIDItem(service, keychainName string) (*StaleTouchIDItem, error) {
	cmd := exec.CommandContext(context.Background(), "/usr/bin/security", "find-generic-password", "-s", service, "-a", TouchIDAccount)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == securityItemNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("security find-generic-password: %w (stderr: %s)", err, bytes.TrimSpace(stderr.Bytes()))
	}
	label := parseSecurityLabel(stdout.String())
	if label == touchIDLabel(keychainName) {
		return nil, nil
	}
	return &StaleTouchIDItem{Service: service, Label: label}, nil
}
