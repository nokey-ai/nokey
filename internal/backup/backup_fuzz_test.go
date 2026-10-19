package backup

import (
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
)

// FuzzDecrypt feeds Decrypt arbitrary blobs. A backup file is read back
// from disk during recovery, so whatever it holds must produce an error,
// never a panic. Each input that clears the length check costs one Argon2id
// derivation, so the seeds are kept few.
func FuzzDecrypt(f *testing.F) {
	minLen := argon2SaltLen + nonceLen + secretbox.Overhead
	valid, err := Encrypt(&Payload{Version: CurrentVersion, Secrets: map[string]string{"K": "v"}}, "pw")
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 0xff

	f.Add([]byte{}, "pw")
	f.Add(make([]byte, minLen-1), "pw")
	f.Add(make([]byte, minLen), "pw")
	f.Add(tampered, "pw")
	f.Add(valid, "wrong")

	f.Fuzz(func(t *testing.T, blob []byte, password string) {
		p, err := Decrypt(blob, password)
		if err == nil && p == nil {
			t.Fatal("Decrypt returned neither a payload nor an error")
		}
	})
}
