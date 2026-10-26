//go:build !darwin

package keyring

// KeychainUnlocked is always false off macOS, where there are no keychain
// files.
func KeychainUnlocked(path string) bool {
	return false
}
