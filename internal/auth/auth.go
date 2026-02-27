package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/nokey-ai/nokey/internal/sensitive"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// PINHash is stored in the keyring under this special key
const PINHashKey = "__nokey_pin_hash__"

// Argon2id parameters
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 2
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// Authenticate prompts the user for their PIN and verifies it against the stored hash
// This ALWAYS requires interactive input from a terminal (cannot be bypassed programmatically)
func Authenticate(storedHash string) error {
	// Verify we're running in an interactive terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("authentication requires an interactive terminal (stdin is not a TTY)\n" +
			"This is a security feature to prevent automated access to secrets")
	}

	// Prompt for PIN
	fmt.Fprintf(os.Stderr, "\n🔐 Authentication Required\n")
	fmt.Fprintf(os.Stderr, "Enter your nokey PIN to access secrets: ")

	// Read PIN without echoing (even works when stdin is not redirected)
	pin, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // Newline after password input

	if err != nil {
		return fmt.Errorf("failed to read PIN: %w", err)
	}

	pinStr := string(pin)
	defer sensitive.ClearString(pinStr)

	// Clear PIN from memory
	for i := range pin {
		pin[i] = 0
	}

	// Verify against stored hash
	ok, err := VerifyPIN(pinStr, storedHash)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("authentication failed: incorrect PIN")
	}

	return nil
}

// HashPINArgon2id creates an Argon2id hash of the PIN, returning a self-describing string:
// $argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
func HashPINArgon2id(pin string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(pin), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPIN verifies a PIN against an encoded hash string.
// Supports both Argon2id (preferred) and legacy SHA-256 hashes.
func VerifyPIN(pin, encoded string) (bool, error) {
	if strings.HasPrefix(encoded, "$argon2id$") {
		return verifyArgon2id(pin, encoded)
	}
	// Legacy SHA-256 hash (hex-encoded, 64 chars)
	return verifyLegacySHA256(pin, encoded), nil
}

// verifyArgon2id parses and verifies an Argon2id encoded hash
func verifyArgon2id(pin, encoded string) (bool, error) {
	// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid argon2id hash format")
	}

	var memory uint32
	var time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, fmt.Errorf("invalid argon2id parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid salt encoding: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid hash encoding: %w", err)
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey([]byte(pin), salt, time, memory, threads, uint32(len(expectedHash))) //nolint:gosec // len(expectedHash) is always 32 bytes from argon2 output

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1, nil
}

// verifyLegacySHA256 verifies a PIN against a legacy SHA-256 hex hash
// Uses constant-time comparison to prevent timing attacks
func verifyLegacySHA256(pin, storedHex string) bool {
	hash := sha256.Sum256([]byte(pin))
	computedHex := hex.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(computedHex), []byte(storedHex)) == 1
}

// IsLegacyHash returns true if the stored hash is a legacy SHA-256 hash
// (not Argon2id), indicating it should be migrated
func IsLegacyHash(storedHash string) bool {
	return !strings.HasPrefix(storedHash, "$argon2id$")
}

// SetupPIN prompts the user to create a new PIN and returns its hash
func SetupPIN() (string, error) {
	// Verify we're running in an interactive terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("PIN setup requires an interactive terminal")
	}

	fmt.Fprintf(os.Stderr, "\n🔐 PIN Setup\n")
	fmt.Fprintf(os.Stderr, "Create a PIN to protect your secrets (4+ characters recommended)\n\n")

	// First entry
	fmt.Fprintf(os.Stderr, "Enter new PIN: ")
	pin1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read PIN: %w", err)
	}

	if len(pin1) < 4 {
		return "", fmt.Errorf("PIN must be at least 4 characters")
	}

	// Confirm entry
	fmt.Fprintf(os.Stderr, "Confirm PIN: ")
	pin2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read PIN: %w", err)
	}

	// Convert to strings once, then zero the byte slices and defer string cleanup.
	pinStr1 := string(pin1)
	pinStr2 := string(pin2)
	defer sensitive.ClearString(pinStr1)
	defer sensitive.ClearString(pinStr2)
	for i := range pin1 {
		pin1[i] = 0
	}
	for i := range pin2 {
		pin2[i] = 0
	}

	// Verify they match
	if pinStr1 != pinStr2 {
		return "", fmt.Errorf("PINs do not match")
	}

	// Hash the PIN with Argon2id
	hash, err := HashPINArgon2id(pinStr1)

	if err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "\n✅ PIN created successfully\n")
	fmt.Fprintf(os.Stderr, "⚠️  Keep this PIN safe - it cannot be recovered if lost\n\n")

	return hash, nil
}

// ChangePIN prompts the user to change their PIN, verifying the old one first
func ChangePIN(oldHash string) (string, error) {
	// Verify old PIN first
	fmt.Fprintf(os.Stderr, "\n🔐 Change PIN\n")
	fmt.Fprintf(os.Stderr, "First, verify your current PIN\n")
	if err := Authenticate(oldHash); err != nil {
		return "", err
	}

	// Now set up new PIN
	return SetupPIN()
}
