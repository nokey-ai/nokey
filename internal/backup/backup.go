// Package backup produces sealed, password-protected snapshots of nokey
// secrets. The dedicated-keychain migration (v0.5.0) uses these snapshots
// as a safety net: secrets are exported and sealed on disk before any
// destructive move, so a failed migration can always be recovered from
// the backup using the user's PIN (or, when no PIN is configured, a
// passphrase the user supplies at backup time).
//
// On-disk layout of an encrypted blob:
//
//	salt(16) || nonce(24) || secretbox-ciphertext
//
// The key is derived from the password and the embedded salt with
// Argon2id using the same parameters as internal/auth, and the
// ciphertext is sealed with NaCl secretbox (XSalsa20-Poly1305) — the
// same primitive internal/audit uses for the audit log. Reusing the
// existing primitives keeps the project's crypto surface area small.
package backup

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// CurrentVersion is the schema version embedded in every backup payload.
// Bump this whenever the payload shape changes so future readers can
// detect and reject incompatible blobs.
const CurrentVersion = 1

// Argon2id parameters — kept identical to internal/auth.HashPINArgon2id
// so a single password-derivation cost profile applies across the
// project. Changing these parameters silently would break decryption of
// any backups produced under the old profile.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 2
	argon2KeyLen  = 32
	argon2SaltLen = 16
	nonceLen      = 24
)

// Payload is the plaintext form of a backup. The map values are the raw
// secret strings; callers are responsible for not leaving copies in
// memory longer than necessary.
type Payload struct {
	Version   int               `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Secrets   map[string]string `json:"secrets"`
}

// Encrypt seals payload with a key derived from password and a fresh
// random salt. The returned bytes contain:
//
//	salt(16) || nonce(24) || secretbox-ciphertext
//
// An empty password is rejected so a missing-PIN bug at the call site
// cannot quietly produce a backup that anyone with the file can read.
func Encrypt(payload *Payload, password string) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("backup: payload is nil")
	}
	if password == "" {
		return nil, errors.New("backup: password is required")
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("backup: marshal payload: %w", err)
	}

	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("backup: generate salt: %w", err)
	}

	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("backup: generate nonce: %w", err)
	}

	key := deriveKey(password, salt)

	// Layout: salt || nonce || secretbox(plaintext, nonce, key)
	out := make([]byte, 0, argon2SaltLen+nonceLen+len(plaintext)+secretbox.Overhead)
	out = append(out, salt...)
	out = append(out, nonce[:]...)
	out = secretbox.Seal(out, plaintext, &nonce, key)

	return out, nil
}

// Decrypt reverses Encrypt. It returns a distinct error for a blob that
// is too short to be valid versus one whose ciphertext fails the
// secretbox authentication check (which covers both a wrong password
// and any tampering of salt, nonce, or ciphertext).
func Decrypt(blob []byte, password string) (*Payload, error) {
	if password == "" {
		return nil, errors.New("backup: password is required")
	}
	if len(blob) < argon2SaltLen+nonceLen+secretbox.Overhead {
		return nil, errors.New("backup: blob truncated")
	}

	salt := blob[:argon2SaltLen]
	var nonce [nonceLen]byte
	copy(nonce[:], blob[argon2SaltLen:argon2SaltLen+nonceLen])
	ciphertext := blob[argon2SaltLen+nonceLen:]

	key := deriveKey(password, salt)

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, key)
	if !ok {
		return nil, errors.New("backup: decryption failed (wrong password or tampered blob)")
	}

	var p Payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("backup: parse payload: %w", err)
	}
	return &p, nil
}

// Write writes blob to path with 0600 permissions, creating the parent
// directory (0700) if it does not exist. The write is atomic: blob is
// staged in a sibling temp file and renamed into place, so a crash
// mid-write cannot leave a half-written backup at path. If the rename
// fails, the temp file is cleaned up.
func Write(path string, blob []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("backup: create dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".backup-*.tmp")
	if err != nil {
		return fmt.Errorf("backup: create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// On any error past this point, scrub the temp file so we never
	// leave a partial blob lying around in the backups directory.
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("backup: write: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("backup: chmod: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("backup: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("backup: close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("backup: rename: %w", err)
	}
	return nil
}

// Read reads a backup file. It is a thin wrapper around os.ReadFile so
// callers can pair it with Decrypt without importing os just to read
// one path.
func Read(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("backup: read %s: %w", path, err)
	}
	return data, nil
}

// DefaultPath returns the canonical backup path for the v0.5.0
// pre-migration snapshot under configDir. The timestamp is rendered in
// UTC with colons replaced by dashes so the path is safe on every
// filesystem (notably Windows, which forbids ':' in filenames).
func DefaultPath(configDir string, now time.Time) string {
	stamp := now.UTC().Format("2006-01-02T15-04-05Z")
	name := fmt.Sprintf("v0.5.0-pre-migration-%s.enc", stamp)
	return filepath.Join(configDir, "backups", name)
}

// deriveKey runs Argon2id with the project-wide parameters and returns
// the result as a *[32]byte ready for secretbox.
func deriveKey(password string, salt []byte) *[32]byte {
	raw := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	var key [32]byte
	copy(key[:], raw)
	return &key
}
