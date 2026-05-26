//go:build !darwin

package keyring

// ApplyKeychainSettings is a no-op on non-macOS platforms. The dedicated
// keychain concept only applies to macOS's Security framework.
func ApplyKeychainSettings(keychainPath string) error {
	return nil
}
