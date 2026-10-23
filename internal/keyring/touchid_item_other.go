//go:build !darwin

package keyring

// FindStaleTouchIDItem is a no-op on non-macOS platforms, which have no
// dedicated keychain or Touch ID item.
func FindStaleTouchIDItem(service, keychainName string) (*StaleTouchIDItem, error) {
	return nil, nil
}
