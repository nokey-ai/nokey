package keyring

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/nokey-ai/nokey/internal/sensitive"

	"github.com/99designs/keyring"
	"github.com/nokey-ai/nokey/internal/auth"
	"golang.org/x/term"
)

// Store wraps the keyring library and provides nokey-specific functionality
type Store struct {
	ring        keyring.Keyring
	serviceName string
	cache       map[string]keyring.Item
}

// NewWithRing creates a Store backed by an existing keyring.Keyring implementation.
// Primarily useful for testing with in-memory or mock backends.
func NewWithRing(ring keyring.Keyring, serviceName string) *Store {
	if serviceName == "" {
		serviceName = "nokey"
	}
	return &Store{ring: ring, serviceName: serviceName, cache: make(map[string]keyring.Item)}
}

// New creates a new keyring store with the specified backend and service name
// If backend is empty, the default backend for the platform is used
func New(backend, serviceName string) (*Store, error) {
	if serviceName == "" {
		serviceName = "nokey"
	}

	var backendType keyring.BackendType
	if backend != "" {
		backendType = keyring.BackendType(backend)
	} else {
		// Use the default backend for the platform
		backendType = keyring.BackendType("")
	}

	config := keyring.Config{
		ServiceName:              serviceName,
		AllowedBackends:          []keyring.BackendType{backendType},
		KeychainTrustApplication: true,
		FileDir:                  getFileBackendDir(),
		FilePasswordFunc:         filePasswordPrompt,
	}

	// If no specific backend, allow all backends
	if backend == "" {
		config.AllowedBackends = nil
	}

	ring, err := keyringOpenFn(config)
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	return &Store{
		ring:        ring,
		serviceName: serviceName,
		cache:       make(map[string]keyring.Item),
	}, nil
}

// Set stores a secret value for the given key
func (s *Store) Set(key, value string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	item := keyring.Item{
		Key:   key,
		Data:  []byte(value),
		Label: "nokey: " + key,
	}

	if err := s.ring.Set(item); err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	s.cache[key] = item
	return nil
}

// Get retrieves a secret value for the given key
func (s *Store) Get(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}

	if item, ok := s.cache[key]; ok {
		return string(item.Data), nil
	}

	item, err := s.ring.Get(key)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			return "", fmt.Errorf("secret not found: %s", key)
		}
		return "", fmt.Errorf("failed to retrieve secret: %w", err)
	}

	s.cache[key] = item
	return string(item.Data), nil
}

// Delete removes a secret for the given key
func (s *Store) Delete(key string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	if err := s.ring.Remove(key); err != nil {
		if err == keyring.ErrKeyNotFound {
			return fmt.Errorf("secret not found: %s", key)
		}
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	delete(s.cache, key)
	return nil
}

// List returns all stored secret keys (not values)
// Filters out internal keys like the PIN hash
func (s *Store) List() ([]string, error) {
	keys, err := s.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Filter out internal keys (PIN hash)
	filtered := make([]string, 0, len(keys))
	for _, key := range keys {
		if !strings.HasPrefix(key, "__nokey_") {
			filtered = append(filtered, key)
		}
	}

	// Sort keys for consistent output
	sort.Strings(filtered)

	return filtered, nil
}

// GetAll retrieves all secrets as a map of key-value pairs
func (s *Store) GetAll() (map[string]string, error) {
	keys, err := s.List()
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]string, len(keys))
	for _, key := range keys {
		value, err := s.Get(key)
		if err != nil {
			return nil, err
		}
		secrets[key] = value
	}

	return secrets, nil
}

// getFileBackendDir returns the directory for the encrypted file backend
func getFileBackendDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return homeDir + "/.config/nokey"
}

// filePasswordPrompt is called when the file backend needs a password
func filePasswordPrompt(prompt string) (string, error) {
	fmt.Fprintf(os.Stderr, "File-based keyring requires a password.\n")
	fmt.Fprintf(os.Stderr, "%s: ", prompt)

	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // Newline after password input
	if err != nil {
		return "", err
	}

	return string(password), nil
}

// HasPIN checks if a PIN is configured
func (s *Store) HasPIN() bool {
	_, err := s.Get(auth.PINHashKey)
	return err == nil
}

// GetPINHash retrieves the stored PIN hash
func (s *Store) GetPINHash() (string, error) {
	val, err := s.Get(auth.PINHashKey)
	if err != nil {
		if IsNotFound(err) {
			return "", fmt.Errorf("no PIN configured (run: nokey auth setup)")
		}
		return "", fmt.Errorf("failed to retrieve PIN hash: %w", err)
	}
	return val, nil
}

// SetPINHash stores the PIN hash
func (s *Store) SetPINHash(hash string) error {
	if err := s.Set(auth.PINHashKey, hash); err != nil {
		return fmt.Errorf("failed to store PIN hash: %w", err)
	}
	return nil
}

// DeletePINHash removes the PIN hash (disables authentication)
func (s *Store) DeletePINHash() error {
	if err := s.Delete(auth.PINHashKey); err != nil {
		if IsNotFound(err) {
			return fmt.Errorf("no PIN configured")
		}
		return fmt.Errorf("failed to delete PIN: %w", err)
	}
	return nil
}

// keyringOpenFn is the function used to open a keyring backend. Overridable for testing.
var keyringOpenFn = keyring.Open

// authenticateFn is the function used to verify PIN auth. Overridable for testing.
var authenticateFn = auth.Authenticate

// AuthenticatedGetAll retrieves all secrets after authenticating with PIN
// This provides zero-trust security: even if Claude runs this command,
// it cannot access secrets without a human entering the PIN
func (s *Store) AuthenticatedGetAll() (map[string]string, error) {
	// Get the stored PIN hash
	storedHash, err := s.GetPINHash()
	if err != nil {
		return nil, err
	}

	// Require human to enter PIN
	if err := authenticateFn(storedHash); err != nil {
		return nil, err
	}

	// Warn if using legacy SHA-256 hash — can't auto-migrate without the raw PIN
	if auth.IsLegacyHash(storedHash) {
		fmt.Fprintf(os.Stderr, "⚠️  Your PIN uses legacy hashing. Run 'nokey auth change' to upgrade to Argon2id.\n")
	}

	// PIN verified, return secrets
	return s.GetAll()
}

// AllKeys returns all stored keys, including internal __nokey_* keys.
// Unlike List(), this does not filter out internal keys.
func (s *Store) AllKeys() ([]string, error) {
	keys, err := s.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}

// MigrateAllItems re-creates all keychain items so they pick up the current
// keyring.Config (notably KeychainTrustApplication). On non-macOS platforms
// this is a no-op.
func (s *Store) MigrateAllItems(dryRun bool) (int, error) {
	if runtime.GOOS != "darwin" {
		return 0, nil
	}

	keys, err := s.ring.Keys()
	if err != nil {
		return 0, fmt.Errorf("failed to enumerate keys: %w", err)
	}

	// Read all values into memory first (safety: data preserved if crash mid-migration)
	type entry struct {
		key  string
		item keyring.Item
	}
	entries := make([]entry, 0, len(keys))
	for _, k := range keys {
		item, err := s.ring.Get(k)
		if err != nil {
			return 0, fmt.Errorf("failed to read key %q: %w", k, err)
		}
		entries = append(entries, entry{key: k, item: item})
	}

	if dryRun {
		return len(entries), nil
	}

	// Deep-copy Data so zeroing entries doesn't corrupt the backend's storage
	for i := range entries {
		entries[i].item.Data = bytes.Clone(entries[i].item.Data)
	}

	// Zero all loaded secret data on every exit path (including errors).
	defer func() {
		for i := range entries {
			sensitive.ClearBytes(entries[i].item.Data)
		}
	}()

	// Re-create each item to pick up new ACL. We remove first, then set —
	// removal is required because macOS Keychain does not update ACLs on
	// an in-place Set. If Set fails after Remove, we retry once before
	// giving up so that a transient error doesn't cause data loss (the
	// original value is still held in memory in `entries`).
	for _, e := range entries {
		if err := s.ring.Remove(e.key); err != nil {
			return 0, fmt.Errorf("failed to remove key %q during migration: %w", e.key, err)
		}
		if err := s.ring.Set(e.item); err != nil {
			// Retry once — the item was just removed, a transient failure
			// here would lose data if we don't try again.
			if retryErr := s.ring.Set(e.item); retryErr != nil {
				return 0, fmt.Errorf("failed to re-create key %q during migration (data may need manual recovery): retry: %w (original: %v)", e.key, retryErr, err)
			}
		}
		// Cache a deep copy — the deferred zeroing will zero entries' backing arrays
		cached := e.item
		cached.Data = bytes.Clone(e.item.Data)
		s.cache[e.key] = cached
	}

	return len(entries), nil
}

// keychainMigratedKey is a sentinel written after MigrateAllItems succeeds.
const keychainMigratedKey = "__nokey_keychain_migrated__"

// IsKeychainMigrated returns true if the keychain migration sentinel exists.
func (s *Store) IsKeychainMigrated() bool {
	val, err := s.Get(keychainMigratedKey)
	return err == nil && val == "1"
}

// SetKeychainMigrated writes the migration sentinel key.
func (s *Store) SetKeychainMigrated() error {
	return s.Set(keychainMigratedKey, "1")
}

// IsNotFound returns true if the error indicates a key was not found in the keyring
func IsNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "secret not found:")
}
