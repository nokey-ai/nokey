package auth

import (
	"crypto/sha256"
	"encoding/hex"
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
