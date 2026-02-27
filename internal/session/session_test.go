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
