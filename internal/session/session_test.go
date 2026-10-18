package session

import (
	"os"
	"path/filepath"
	"runtime"
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
		{"", 15 * time.Minute, false},
		{"5m", 5 * time.Minute, false},
		{"30s", 30 * time.Second, false},
		{"1h", 1 * time.Hour, false},
		{"4h", 4 * time.Hour, false},
		{"8h", 8 * time.Hour, false},
		{"9h", 0, true},  // exceeds max
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

func TestValid_TouchedTicketRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()

	// Backdate the ticket past its TTL, then "touch" it back to now. A
	// ticket whose mtime no longer matches its issue time must not validate.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if Valid("hash", 5*time.Minute) {
		t.Fatal("expected backdated ticket to be expired")
	}

	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if Valid("hash", 5*time.Minute) {
		t.Error("expected touched ticket to be rejected")
	}
}

func TestValid_FutureMtimeRejected(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, err := ticketPath()
	if err != nil {
		t.Fatalf("ticketPath: %v", err)
	}

	// A correctly signed ticket whose issue time is in the future would
	// otherwise never expire.
	future := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	if err := writeTicket(path, "hash", future); err != nil {
		t.Fatalf("writeTicket: %v", err)
	}
	if Valid("hash", 5*time.Minute) {
		t.Error("expected ticket with future mtime to be rejected")
	}
}

func TestValid_SymlinkRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()

	target := filepath.Join(home, "elsewhere")
	if err := os.Rename(path, target); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if Valid("hash", 5*time.Minute) {
		t.Error("expected symlinked ticket to be rejected")
	}
}

func TestValid_GroupReadableRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not meaningful on Windows")
	}
	t.Setenv("HOME", t.TempDir())
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if Valid("hash", 5*time.Minute) {
		t.Error("expected group-readable ticket to be rejected")
	}
}

func TestValid_ExpiredTicketDeleted(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path, _ := ticketPath()
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if Valid("hash", 5*time.Minute) {
		t.Fatal("expected expired ticket to be invalid")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("expected expired ticket to be removed, Lstat err = %v", err)
	}
}

func TestCreate_DoesNotFollowSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path, err := ticketPath()
	if err != nil {
		t.Fatalf("ticketPath: %v", err)
	}
	target := filepath.Join(home, "victim")
	if err := os.WriteFile(target, []byte("original"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Errorf("Create wrote through symlink: target now %q", got)
	}
	if !Valid("hash", 5*time.Minute) {
		t.Error("expected fresh ticket to replace the symlink and validate")
	}
}

func TestCreate_TightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not meaningful on Windows")
	}
	t.Setenv("HOME", t.TempDir())
	path, _ := ticketPath()
	if err := os.WriteFile(path, []byte("stale"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("ticket perms = %o, want 0600", perm)
	}
}

func TestClear_RemovesLeftoverTempFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, err := ticketPath()
	if err != nil {
		t.Fatalf("ticketPath: %v", err)
	}
	// A crash between CreateTemp and Rename in writeTicket leaves one behind.
	leftover := path + ".123456"
	if err := os.WriteFile(leftover, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Create("hash"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := os.Lstat(leftover); !os.IsNotExist(err) {
		t.Errorf("expected leftover temp ticket to be removed, Lstat err = %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("expected ticket to be removed, Lstat err = %v", err)
	}
}
