package backup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// samplePayload returns a payload covering ASCII keys and a variety of
// nasty-looking values (multi-line, quotes, backslashes, unicode) so
// every JSON-encoding test exercises the same realistic input.
func samplePayload(t *testing.T) *Payload {
	t.Helper()
	return &Payload{
		Version:   CurrentVersion,
		Timestamp: time.Date(2026, 5, 24, 1, 23, 45, 0, time.UTC),
		Secrets: map[string]string{
			"OPENAI_API_KEY": "sk-test-123",
			"DB_URL":         "postgres://user:p@ss/db",
			"MULTILINE":      "line1\nline2\nline3",
			"QUOTES":         `he said "hi" \\ goodbye`,
			"UNICODE":        "café-π-🔐",
			"EMPTY":          "",
		},
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	want := samplePayload(t)

	blob, err := Encrypt(want, "correct-horse")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(blob, "correct-horse")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if got.Version != want.Version {
		t.Errorf("version: got %d, want %d", got.Version, want.Version)
	}
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("timestamp: got %v, want %v", got.Timestamp, want.Timestamp)
	}
	if !reflect.DeepEqual(got.Secrets, want.Secrets) {
		t.Errorf("secrets mismatch:\n got: %#v\nwant: %#v", got.Secrets, want.Secrets)
	}
}

func TestEncryptProducesFreshSaltAndNonce(t *testing.T) {
	// Two encryptions of the same payload with the same password must
	// produce different ciphertexts; otherwise nonce or salt reuse
	// would be silently undermining the seal.
	p := samplePayload(t)
	a, err := Encrypt(p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(p, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions produced identical bytes; salt or nonce reuse?")
	}
	if bytes.Equal(a[:argon2SaltLen], b[:argon2SaltLen]) {
		t.Fatal("salt reused across encryptions")
	}
}

func TestDecryptWrongPasswordFails(t *testing.T) {
	blob, err := Encrypt(samplePayload(t), "a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(blob, "b"); err == nil {
		t.Fatal("decrypt with wrong password should fail")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	blob, err := Encrypt(samplePayload(t), "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext portion (after salt+nonce).
	tampered := append([]byte(nil), blob...)
	idx := argon2SaltLen + nonceLen + 2
	tampered[idx] ^= 0xff
	if _, err := Decrypt(tampered, "pw"); err == nil {
		t.Fatal("decrypt of tampered ciphertext should fail")
	}
}

func TestDecryptTamperedSaltFails(t *testing.T) {
	blob, err := Encrypt(samplePayload(t), "pw")
	if err != nil {
		t.Fatal(err)
	}
	// Flipping a salt byte changes the derived key, so secretbox.Open
	// must fail authentication. This guards against an attacker who
	// edits the salt hoping to coerce a known-key derivation.
	tampered := append([]byte(nil), blob...)
	tampered[0] ^= 0xff
	if _, err := Decrypt(tampered, "pw"); err == nil {
		t.Fatal("decrypt with tampered salt should fail")
	}
}

func TestDecryptTruncatedBlobErrorsGracefully(t *testing.T) {
	cases := map[string][]byte{
		"empty":          nil,
		"salt-only":      make([]byte, argon2SaltLen),
		"salt-and-nonce": make([]byte, argon2SaltLen+nonceLen),
		"one-byte":       {0x00},
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			// Must return an error, not panic.
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			if _, err := Decrypt(blob, "pw"); err == nil {
				t.Fatal("expected error for truncated blob")
			}
		})
	}
}

func TestEncryptRejectsEmptyPassword(t *testing.T) {
	// A no-PIN footgun would silently produce a backup that any reader
	// of the file could decrypt; refuse instead.
	if _, err := Encrypt(samplePayload(t), ""); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestEncryptRejectsNilPayload(t *testing.T) {
	if _, err := Encrypt(nil, "pw"); err == nil {
		t.Fatal("expected error for nil payload")
	}
}

func TestDecryptRejectsEmptyPassword(t *testing.T) {
	if _, err := Decrypt(make([]byte, 200), ""); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.enc")
	blob := []byte("opaque bytes that look encrypted")

	if err := Write(path, blob); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("round-trip mismatch:\n got: %q\nwant: %q", got, blob)
	}
}

func TestWriteCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deeply", "nested", "missing", "backup.enc")
	if err := Write(path, []byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestWriteUses0600Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not apply on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.enc")
	if err := Write(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("permissions: got %#o, want 0600", mode)
	}
}

func TestWriteAtomicLeavesNoPartialFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based read-only dir doesn't behave the same on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}

	dir := t.TempDir()
	// Make a child dir, then read-only. We'll point Write at a file
	// inside an UNCREATED grandchild of the read-only dir, so MkdirAll
	// fails — no temp file ever gets created.
	parent := filepath.Join(dir, "ro")
	if err := os.Mkdir(parent, 0500); err != nil {
		t.Fatal(err)
	}
	// Restore perms at end so t.TempDir cleanup works.
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })

	path := filepath.Join(parent, "new-subdir", "backup.enc")
	if err := Write(path, []byte("x")); err == nil {
		t.Fatal("expected Write to fail under read-only parent")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected target to not exist; stat err: %v", err)
	}
	// And no stray .backup-*.tmp left in the parent (which is itself
	// read-only, so MkdirAll fails before CreateTemp can run).
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".backup-") {
			t.Fatalf("stray temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteAtomicCleansTempOnRenameFailure(t *testing.T) {
	// If rename fails (e.g. target is a directory), the temp file
	// staged in the same dir must be cleaned up.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Write(target, []byte("x")); err == nil {
		t.Fatal("expected rename onto a directory to fail")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".backup-") {
			t.Fatalf("stray temp file: %s", e.Name())
		}
	}
}

func TestDefaultPathFormatting(t *testing.T) {
	// Fixed instant in a non-UTC zone — DefaultPath must normalize to
	// UTC so two machines in different timezones produce comparable
	// filenames at the same wall clock moment.
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 24, 21, 23, 45, 0, loc) // 01:23:45Z next day
	got := DefaultPath("/home/me/.config/nokey", now)
	want := filepath.Join("/home/me/.config/nokey", "backups", "v0.5.0-pre-migration-2026-05-25T01-23-45Z.enc")
	if got != want {
		t.Errorf("DefaultPath:\n got: %s\nwant: %s", got, want)
	}
}

func TestPayloadJSONRoundTripEdgeCases(t *testing.T) {
	cases := map[string]*Payload{
		"empty-secrets": {
			Version:   CurrentVersion,
			Timestamp: time.Now().UTC().Truncate(time.Second),
			Secrets:   map[string]string{},
		},
		"multiline-and-quotes": {
			Version:   CurrentVersion,
			Timestamp: time.Now().UTC().Truncate(time.Second),
			Secrets: map[string]string{
				"K1": "line1\nline2\r\nline3",
				"K2": `"quoted"`,
				"K3": `back\\slash`,
				"K4": "tab\there",
			},
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			blob, err := Encrypt(p, "pw")
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decrypt(blob, "pw")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Secrets, p.Secrets) {
				t.Errorf("secrets mismatch:\n got: %#v\nwant: %#v", got.Secrets, p.Secrets)
			}
			if !got.Timestamp.Equal(p.Timestamp) {
				t.Errorf("timestamp mismatch: got %v want %v", got.Timestamp, p.Timestamp)
			}
			// Sanity: the embedded plaintext must be valid JSON
			// matching our schema (guards against a future change that
			// drops a field but doesn't update tests).
			raw, _ := json.Marshal(p)
			var rt Payload
			if err := json.Unmarshal(raw, &rt); err != nil {
				t.Fatalf("payload JSON not parseable: %v", err)
			}
		})
	}
}
