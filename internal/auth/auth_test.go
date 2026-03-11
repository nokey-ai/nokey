package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestHashPINArgon2id(t *testing.T) {
	hash, err := HashPINArgon2id("testpin")
	if err != nil {
		t.Fatalf("HashPINArgon2id failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("Hash should start with $argon2id$v=19$, got: %s", hash)
	}

	// Verify the hash has the expected number of parts
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("Expected 6 parts in hash, got %d: %s", len(parts), hash)
	}
}

func TestHashPINArgon2id_UniqueSalts(t *testing.T) {
	hash1, err := HashPINArgon2id("testpin")
	if err != nil {
		t.Fatalf("First hash failed: %v", err)
	}

	hash2, err := HashPINArgon2id("testpin")
	if err != nil {
		t.Fatalf("Second hash failed: %v", err)
	}

	if hash1 == hash2 {
		t.Error("Two hashes of the same PIN should have different salts")
	}
}

func TestVerifyPIN_Argon2id(t *testing.T) {
	pin := "mysecretpin"
	hash, err := HashPINArgon2id(pin)
	if err != nil {
		t.Fatalf("HashPINArgon2id failed: %v", err)
	}

	// Correct PIN should verify
	ok, err := VerifyPIN(pin, hash)
	if err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}
	if !ok {
		t.Error("VerifyPIN should return true for correct PIN")
	}

	// Wrong PIN should not verify
	ok, err = VerifyPIN("wrongpin", hash)
	if err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}
	if ok {
		t.Error("VerifyPIN should return false for wrong PIN")
	}
}

func TestVerifyPIN_LegacySHA256(t *testing.T) {
	pin := "testpin"
	// Compute the correct SHA-256 hex hash
	h := sha256.Sum256([]byte(pin))
	legacyHash := hex.EncodeToString(h[:])

	// Correct PIN should verify against legacy hash
	ok, err := VerifyPIN(pin, legacyHash)
	if err != nil {
		t.Fatalf("VerifyPIN with legacy hash should not error: %v", err)
	}
	if !ok {
		t.Error("VerifyPIN should return true for correct PIN with legacy hash")
	}

	// Wrong PIN should not verify
	ok, err = VerifyPIN("wrongpin", legacyHash)
	if err != nil {
		t.Fatalf("VerifyPIN failed: %v", err)
	}
	if ok {
		t.Error("VerifyPIN should return false for wrong PIN with legacy hash")
	}
}

func TestIsLegacyHash(t *testing.T) {
	tests := []struct {
		hash     string
		isLegacy bool
	}{
		{"$argon2id$v=19$m=65536,t=3,p=2$salt$hash", false},
		{"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", true},
		{"", true},
	}

	for _, tt := range tests {
		if got := IsLegacyHash(tt.hash); got != tt.isLegacy {
			t.Errorf("IsLegacyHash(%q) = %v, want %v", tt.hash, got, tt.isLegacy)
		}
	}
}

// --- helpers to override terminal functions ---

func stubTerminal(t *testing.T, isTerm bool, passwords ...[]byte) {
	t.Helper()
	oldIsTerminal := isTerminalFn
	oldReadPassword := readPasswordFn
	oldStderr := stderrWriter
	t.Cleanup(func() {
		isTerminalFn = oldIsTerminal
		readPasswordFn = oldReadPassword
		stderrWriter = oldStderr
	})

	isTerminalFn = func(fd int) bool { return isTerm }
	stderrWriter = io.Discard // silence prompts

	callIdx := 0
	readPasswordFn = func(fd int) ([]byte, error) {
		if callIdx >= len(passwords) {
			return nil, fmt.Errorf("unexpected readPassword call %d", callIdx)
		}
		p := passwords[callIdx]
		callIdx++
		return p, nil
	}
}

// --- Authenticate ---

func TestAuthenticate_Success(t *testing.T) {
	pin := "securepin123"
	hash, err := HashPINArgon2id(pin)
	if err != nil {
		t.Fatalf("HashPINArgon2id: %v", err)
	}

	stubTerminal(t, true, []byte(pin))

	if err := Authenticate(hash); err != nil {
		t.Errorf("Authenticate should succeed: %v", err)
	}
}

func TestAuthenticate_WrongPIN(t *testing.T) {
	hash, _ := HashPINArgon2id("correctpin")
	stubTerminal(t, true, []byte("wrongpin"))

	if err := Authenticate(hash); err == nil {
		t.Error("Authenticate should fail with wrong PIN")
	}
}

func TestAuthenticate_NotTerminal(t *testing.T) {
	hash, _ := HashPINArgon2id("1234")
	stubTerminal(t, false)

	err := Authenticate(hash)
	if err == nil {
		t.Fatal("Authenticate should fail when not a terminal")
	}
	if !strings.Contains(err.Error(), "interactive terminal") {
		t.Errorf("error should mention interactive terminal, got: %v", err)
	}
}

func TestAuthenticate_LegacySHA256(t *testing.T) {
	pin := "legacypin"
	h := sha256.Sum256([]byte(pin))
	legacyHash := hex.EncodeToString(h[:])

	stubTerminal(t, true, []byte(pin))

	if err := Authenticate(legacyHash); err != nil {
		t.Errorf("Authenticate with legacy hash should succeed: %v", err)
	}
}

// --- SetupPIN ---

func TestSetupPIN_Success(t *testing.T) {
	// Pass separate copies since SetupPIN zeroes the byte slices
	stubTerminal(t, true, []byte("newpin1234"), []byte("newpin1234"))

	hash, err := SetupPIN()
	if err != nil {
		t.Fatalf("SetupPIN: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should be argon2id, got: %s", hash)
	}

	// Verify the hash works
	ok, err := VerifyPIN("newpin1234", hash)
	if err != nil {
		t.Fatalf("VerifyPIN: %v", err)
	}
	if !ok {
		t.Error("hash should verify with the correct PIN")
	}
}

func TestSetupPIN_TooShort(t *testing.T) {
	stubTerminal(t, true, []byte("abc"))

	_, err := SetupPIN()
	if err == nil {
		t.Fatal("SetupPIN should fail with short PIN")
	}
	if !strings.Contains(err.Error(), "at least 4") {
		t.Errorf("error should mention length requirement, got: %v", err)
	}
}

func TestSetupPIN_Mismatch(t *testing.T) {
	stubTerminal(t, true, []byte("pin12345"), []byte("different"))

	_, err := SetupPIN()
	if err == nil {
		t.Fatal("SetupPIN should fail when PINs don't match")
	}
	if !strings.Contains(err.Error(), "do not match") {
		t.Errorf("error should mention mismatch, got: %v", err)
	}
}

func TestSetupPIN_NotTerminal(t *testing.T) {
	stubTerminal(t, false)

	_, err := SetupPIN()
	if err == nil {
		t.Fatal("SetupPIN should fail when not a terminal")
	}
	if !strings.Contains(err.Error(), "interactive terminal") {
		t.Errorf("error should mention terminal, got: %v", err)
	}
}

// --- ChangePIN ---

func TestChangePIN_Success(t *testing.T) {
	oldPIN := "oldpin1234"
	newPIN := "newpin5678"

	oldHash, err := HashPINArgon2id(oldPIN)
	if err != nil {
		t.Fatalf("HashPINArgon2id: %v", err)
	}

	// ChangePIN calls Authenticate (1 read) then SetupPIN (2 reads)
	stubTerminal(t, true, []byte(oldPIN), []byte(newPIN), []byte(newPIN))

	newHash, err := ChangePIN(oldHash)
	if err != nil {
		t.Fatalf("ChangePIN: %v", err)
	}

	ok, err := VerifyPIN(newPIN, newHash)
	if err != nil {
		t.Fatalf("VerifyPIN: %v", err)
	}
	if !ok {
		t.Error("new hash should verify with new PIN")
	}
}

func TestChangePIN_WrongOldPIN(t *testing.T) {
	oldHash, _ := HashPINArgon2id("correctold")
	stubTerminal(t, true, []byte("wrongold"))

	_, err := ChangePIN(oldHash)
	if err == nil {
		t.Fatal("ChangePIN should fail with wrong old PIN")
	}
}

// --- verifyArgon2id edge cases ---

func TestVerifyArgon2id_InvalidFormat(t *testing.T) {
	_, err := VerifyPIN("test", "$argon2id$bad")
	if err == nil {
		t.Error("should fail with invalid format")
	}
}

func TestVerifyArgon2id_InvalidParams(t *testing.T) {
	_, err := VerifyPIN("test", "$argon2id$v=19$bad_params$salt$hash")
	if err == nil {
		t.Error("should fail with invalid params")
	}
}

func TestVerifyArgon2id_InvalidSaltEncoding(t *testing.T) {
	_, err := VerifyPIN("test", "$argon2id$v=19$m=65536,t=3,p=2$!!!invalid!!!$hash")
	if err == nil {
		t.Error("should fail with invalid salt encoding")
	}
}

func TestVerifyArgon2id_InvalidHashEncoding(t *testing.T) {
	_, err := VerifyPIN("test", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdA$!!!invalid!!!")
	if err == nil {
		t.Error("should fail with invalid hash encoding")
	}
}
