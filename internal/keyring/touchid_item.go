package keyring

import (
	"fmt"
	"regexp"
)

// TouchIDAccount is the login-keychain account under which byteness/keyring
// stores the dedicated keychain's passphrase for Touch ID unlock.
const TouchIDAccount = "com.nokey.biometrics"

// touchIDLabel mirrors byteness/keyring's label for the Touch ID item. The
// library looks the item up by service, account and this label, but macOS
// treats service and account alone as the item's identity.
func touchIDLabel(keychainName string) string {
	return fmt.Sprintf("Passphrase for %s.keychain", keychainName)
}

// StaleTouchIDItem describes a Touch ID item in the login keychain that was
// written for a different dedicated keychain. byteness/keyring can't see it
// (the label differs) and can't replace it (the service and account match),
// so first-time Touch ID setup fails with errSecDuplicateItem (-25299).
type StaleTouchIDItem struct {
	Service string
	Label   string
}

// DeleteCommand is the shell command that removes the stale item.
func (s *StaleTouchIDItem) DeleteCommand() string {
	return fmt.Sprintf("security delete-generic-password -s %s -a %s", s.Service, TouchIDAccount)
}

// securityLabelRe matches the label attribute in `security
// find-generic-password` output, which prints it either as "labl" or as
// its raw attribute number 0x00000007.
var securityLabelRe = regexp.MustCompile(`(?m)^\s*(?:"labl"|0x00000007)\s*<blob>=(?:"(.*)"|<NULL>)\s*$`)

// parseSecurityLabel extracts the item label from `security
// find-generic-password` output. A missing or NULL label returns "".
func parseSecurityLabel(out string) string {
	m := securityLabelRe.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}
