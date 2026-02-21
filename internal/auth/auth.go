package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
)

// PINHash is stored in the keyring under this special key
const PINHashKey = "__nokey_pin_hash__"

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

	// Hash the entered PIN
	enteredHash := HashPIN(string(pin))

	// Clear PIN from memory
	for i := range pin {
		pin[i] = 0
	}

	// Verify hash
	if enteredHash != storedHash {
		return fmt.Errorf("authentication failed: incorrect PIN")
	}

	return nil
}

// HashPIN creates a SHA-256 hash of the PIN
func HashPIN(pin string) string {
	hash := sha256.Sum256([]byte(pin))
	return hex.EncodeToString(hash[:])
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

	// Verify they match
	if string(pin1) != string(pin2) {
		// Clear PINs from memory
		for i := range pin1 {
			pin1[i] = 0
		}
		for i := range pin2 {
			pin2[i] = 0
		}
		return "", fmt.Errorf("PINs do not match")
	}

	// Hash the PIN
	hash := HashPIN(string(pin1))

	// Clear PINs from memory
	for i := range pin1 {
		pin1[i] = 0
	}
	for i := range pin2 {
		pin2[i] = 0
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
