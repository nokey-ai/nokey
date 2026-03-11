package session

import (
	"os"
	"testing"
	"time"
)

func TestCreateAndValid(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	pinHash := "argon2id$v=19$m=65536,t=3,p=2$abc$def"

	if err := Create(pinHash); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !Valid(pinHash, 5*time.Minute) {
		t.Error("expected Valid to return true for correct pinHash")
	}

	if Valid("wrong-hash", 5*time.Minute) {
		t.Error("expected Valid to return false for wrong pinHash")
	}
}

func TestExpiredTicket(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	pinHash := "test-pin-hash"
	if err := Create(pinHash); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// With a zero TTL, the ticket should immediately be expired.
	if Valid(pinHash, 0) {
		t.Error("expected Valid to return false with zero TTL")
	}
}

func TestClear(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	pinHash := "test-pin-hash"
	if err := Create(pinHash); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !Valid(pinHash, 5*time.Minute) {
		t.Fatal("ticket should be valid before clear")
	}

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if Valid(pinHash, 5*time.Minute) {
		t.Error("expected Valid to return false after Clear")
	}
}

func TestClearNoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := Clear(); err != nil {
		t.Errorf("Clear with no file should not error, got: %v", err)
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"", 5 * time.Minute, false},
		{"5m", 5 * time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"1h", 1 * time.Hour, false},
		{"2h", 0, true},  // exceeds max
		{"-5m", 0, true}, // negative
		{"bad", 0, true}, // unparseable
		{"0s", 0, true},  // zero
	}

	for _, tt := range tests {
		t.Run("input="+tt.input, func(t *testing.T) {
			got, err := ParseTTL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseTTL(%q) = %v, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseTTL(%q) error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseTTL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTicketFilePermissions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := Create("test-hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	path, err := ticketPath()
	if err != nil {
		t.Fatalf("ticketPath: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("ticket file permissions = %o, want 0600", perm)
	}
}

func TestValid_InvalidTicketContent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// Create a ticket first to get the path
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()

	// Overwrite with invalid content (no newline separator)
	os.WriteFile(path, []byte("no-newline-here"), 0600)
	if Valid("hash", 5*time.Minute) {
		t.Error("expected false for invalid ticket content (no newline)")
	}
}

func TestValid_InvalidHexToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()

	// Valid format but invalid hex
	os.WriteFile(path, []byte("not-hex-at-all\ndeadbeef"), 0600)
	if Valid("hash", 5*time.Minute) {
		t.Error("expected false for invalid hex token")
	}
}

func TestValid_InvalidHexSignature(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()

	// Valid token hex but invalid signature hex
	os.WriteFile(path, []byte("deadbeef\nnot-hex-sig"), 0600)
	if Valid("hash", 5*time.Minute) {
		t.Error("expected false for invalid hex signature")
	}
}

func TestValid_NoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// No ticket created, Valid should return false
	if Valid("hash", 5*time.Minute) {
		t.Error("expected false when no ticket file exists")
	}
}

func TestTicketDir_CreatesDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir, err := ticketDir()
	if err != nil {
		t.Fatalf("ticketDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected a directory")
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("dir perms = %o, want 0700", info.Mode().Perm())
	}
}

func TestTicketDir_MkdirAllError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	// Place a regular file where the directory should be created,
	// so MkdirAll fails.
	blocker := tempDir + "/.config"
	os.WriteFile(blocker, []byte("not a dir"), 0600)

	_, err := ticketDir()
	if err == nil {
		t.Error("expected error when MkdirAll cannot create directory")
	}
}

func TestCreate_TicketPathError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	// Block directory creation so ticketPath fails
	blocker := tempDir + "/.config"
	os.WriteFile(blocker, []byte("not a dir"), 0600)

	err := Create("hash")
	if err == nil {
		t.Error("expected error when ticketPath fails")
	}
}

func TestValid_UnreadableFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()
	// Make file unreadable
	os.Chmod(path, 0000)
	defer os.Chmod(path, 0600) // cleanup

	if Valid("hash", 5*time.Minute) {
		t.Error("expected false for unreadable ticket file")
	}
}

func TestClear_TicketPathError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	// Block directory creation so ticketPath fails
	blocker := tempDir + "/.config"
	os.WriteFile(blocker, []byte("not a dir"), 0600)

	err := Clear()
	if err == nil {
		t.Error("expected error when ticketPath fails in Clear")
	}
}

func TestValid_TicketPathError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	// Block directory creation so ticketPath fails
	blocker := tempDir + "/.config"
	os.WriteFile(blocker, []byte("not a dir"), 0600)

	if Valid("hash", 5*time.Minute) {
		t.Error("expected false when ticketPath fails")
	}
}
