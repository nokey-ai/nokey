// Package session provides sudo-style PIN session caching.
//
// After a successful PIN verification, a session ticket is written to disk.
// Subsequent exec invocations within the TTL skip the PIN prompt by validating
// the ticket's HMAC against the stored PIN hash. The ticket file's mod time
// determines expiry, and is bound into the HMAC so that changing it (e.g. with
// touch) invalidates the ticket rather than extending it.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const ticketFileName = "session_ticket"

// maxClockSkew is how far in the future a ticket's mod time may be before it
// is rejected. A ticket dated further ahead would otherwise outlive its TTL.
const maxClockSkew = 60 * time.Second

// maxTicketSize bounds how much of the ticket file Valid reads.
const maxTicketSize = 1024

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
	path, err := ticketPath()
	if err != nil {
		return err
	}
	return writeTicket(path, pinHash, time.Now().Truncate(time.Second))
}

// sign returns HMAC-SHA256(pinHash, token || issued unix seconds).
func sign(pinHash string, token []byte, issued time.Time) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(issued.Unix()))
	mac := hmac.New(sha256.New, []byte(pinHash))
	mac.Write(token)
	mac.Write(ts[:])
	return mac.Sum(nil)
}

// writeTicket writes a ticket issued at the given time to path. It writes a
// fresh 0600 temp file and renames it into place, so an existing file or
// symlink at path is replaced rather than written through.
func writeTicket(path, pinHash string, issued time.Time) error {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("failed to generate session token: %w", err)
	}

	content := hex.EncodeToString(token) + "\n" + hex.EncodeToString(sign(pinHash, token, issued))

	tmp, err := os.CreateTemp(filepath.Dir(path), ticketFileName+".*")
	if err != nil {
		return fmt.Errorf("failed to create session ticket: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed

	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write session ticket: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write session ticket: %w", err)
	}
	if err := os.Chtimes(tmpName, issued, issued); err != nil {
		return fmt.Errorf("failed to set session ticket time: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to install session ticket: %w", err)
	}
	return nil
}

// Valid checks whether a non-expired session ticket exists that was created
// with the given pinHash. Returns false on any error. An expired ticket is
// removed.
func Valid(pinHash string, ttl time.Duration) bool {
	path, err := ticketPath()
	if err != nil {
		return false
	}

	// Lstat first so a symlink or FIFO is rejected without opening it.
	linfo, err := os.Lstat(path)
	if err != nil || !linfo.Mode().IsRegular() {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// Judge the file actually opened, and reject it if it was swapped
	// after the Lstat.
	info, err := f.Stat()
	if err != nil || !os.SameFile(linfo, info) {
		return false
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return false
	}

	// Check expiry based on file mod time.
	issued := info.ModTime()
	age := time.Since(issued)
	if age < -maxClockSkew {
		return false
	}
	if age > ttl {
		// Remove only the ticket examined here; a concurrent Create may
		// already have renamed a fresh one into place.
		if cur, err := os.Lstat(path); err == nil && os.SameFile(cur, info) {
			_ = os.Remove(path)
		}
		return false
	}

	data, err := io.ReadAll(io.LimitReader(f, maxTicketSize))
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

	return hmac.Equal(sig, sign(pinHash, token, issued))
}

// Clear removes the session ticket file, along with any temp files a
// crashed Create left behind. Returns nil if the file does not exist.
func Clear() error {
	path, err := ticketPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session ticket: %w", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ticketFileName+".") {
			_ = os.Remove(filepath.Join(filepath.Dir(path), e.Name()))
		}
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
