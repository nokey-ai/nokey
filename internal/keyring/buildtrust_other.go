//go:build !darwin

package keyring

// trustRunningBuild is a no-op off macOS, where keychain partition lists
// don't exist.
func trustRunningBuild(keychainPath, service string, accounts []string) (int, error) {
	return 0, nil
}
