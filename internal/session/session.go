// Package session provides sudo-style PIN session caching.
//
// After a successful PIN verification, a session ticket is written to disk.
// Subsequent exec invocations within the TTL skip the PIN prompt by validating
// the ticket's HMAC against the stored PIN hash. The ticket file's mod time
// determines expiry (no clock data inside the ticket itself).
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const ticketFileName = "session_ticket"

// ticketDir returns ~/.config/nokey and ensures the directory exists.
func ticketDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", "nokey")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}
	return dir, nil
}

// ticketPath returns the full path to the session ticket file.
func ticketPath() (string, error) {
	dir, err := ticketDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ticketFileName), nil
}

// Create generates a new session ticket bound to pinHash and writes it to disk.
func Create(pinHash string) error {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate session token: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(pinHash))
	mac.Write(token)
	sig := mac.Sum(nil)

	content := hex.EncodeToString(token) + "\n" + hex.EncodeToString(sig)

	path, err := ticketPath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

// Valid checks whether a non-expired session ticket exists that was created
// with the given pinHash. Returns false on any error.
func Valid(pinHash string, ttl time.Duration) bool {
	path, err := ticketPath()
	if err != nil {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check expiry based on file mod time.
	if time.Since(info.ModTime()) > ttl {
		return false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	parts := strings.SplitN(string(data), "\n", 2)
	if len(parts) != 2 {
		return false
	}

	token, err := hex.DecodeString(strings.TrimSpace(parts[0]))
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(pinHash))
	mac.Write(token)
	expected := mac.Sum(nil)

	return hmac.Equal(sig, expected)
}

// Clear removes the session ticket file. Returns nil if the file does not exist.
func Clear() error {
	path, err := ticketPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session ticket: %w", err)
	}
	return nil
}

// ParseTTL parses a duration string into a time.Duration.
// An empty string defaults to 15 minutes. Maximum allowed is 8 hours.
func ParseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 15 * time.Minute, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid session TTL %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("session TTL must be positive, got %s", d)
	}
	if d > 8*time.Hour {
		return 0, fmt.Errorf("session TTL %s exceeds maximum of 8h", d)
	}
	return d, nil
}
