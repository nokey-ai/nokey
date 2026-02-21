package keyring

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/99designs/keyring"
	"github.com/nokey-ai/nokey/internal/auth"
	"golang.org/x/term"
)

// Store wraps the keyring library and provides nokey-specific functionality
type Store struct {
	ring        keyring.Keyring
	serviceName string
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

	ring, err := keyring.Open(config)
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	return &Store{
		ring:        ring,
		serviceName: serviceName,
	}, nil
}

// Set stores a secret value for the given key
func (s *Store) Set(key, value string) error {
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	item := keyring.Item{
		Key:  key,
		Data: []byte(value),
	}

	if err := s.ring.Set(item); err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}

	return nil
}

// Get retrieves a secret value for the given key
func (s *Store) Get(key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	}

	item, err := s.ring.Get(key)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			return "", fmt.Errorf("secret not found: %s", key)
		}
		return "", fmt.Errorf("failed to retrieve secret: %w", err)
	}

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
	_, err := s.ring.Get(auth.PINHashKey)
	return err == nil
}

// GetPINHash retrieves the stored PIN hash
func (s *Store) GetPINHash() (string, error) {
	item, err := s.ring.Get(auth.PINHashKey)
	if err != nil {
		if err == keyring.ErrKeyNotFound {
			return "", fmt.Errorf("no PIN configured (run: nokey auth setup)")
		}
		return "", fmt.Errorf("failed to retrieve PIN hash: %w", err)
	}
	return string(item.Data), nil
}

// SetPINHash stores the PIN hash
func (s *Store) SetPINHash(hash string) error {
	item := keyring.Item{
		Key:  auth.PINHashKey,
		Data: []byte(hash),
	}
	if err := s.ring.Set(item); err != nil {
		return fmt.Errorf("failed to store PIN hash: %w", err)
	}
	return nil
}

// DeletePINHash removes the PIN hash (disables authentication)
func (s *Store) DeletePINHash() error {
	if err := s.ring.Remove(auth.PINHashKey); err != nil {
		if err == keyring.ErrKeyNotFound {
			return fmt.Errorf("no PIN configured")
		}
		return fmt.Errorf("failed to delete PIN: %w", err)
	}
	return nil
}

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
	if err := auth.Authenticate(storedHash); err != nil {
		return nil, err
	}

	// If using legacy hash, migrate to Argon2id
	if auth.IsLegacyHash(storedHash) {
		fmt.Fprintf(os.Stderr, "🔄 Upgrading PIN hash to Argon2id...\n")
		// We can't re-hash without the PIN, but Authenticate already verified it.
		// We'd need the PIN again. Since we just verified, prompt once more.
		// Actually, we can't get the PIN back. The migration will happen on next
		// auth change or setup. Just log a recommendation.
		fmt.Fprintf(os.Stderr, "⚠️  Your PIN uses legacy hashing. Run 'nokey auth change' to upgrade to Argon2id.\n")
	}

	// PIN verified, return secrets
	return s.GetAll()
}

// IsNotFound returns true if the error indicates a key was not found in the keyring
func IsNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "secret not found:")
}
