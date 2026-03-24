package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// --- parseSince ---

func TestParseSince_Hours(t *testing.T) {
	before := time.Now().UTC()
	result, err := parseSince("2h")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	expected := before.Add(-2 * time.Hour)
	if result.Before(expected.Add(-time.Second)) || result.After(expected.Add(time.Second)) {
		t.Errorf("parseSince(2h) = %v, want ~%v", result, expected)
	}
}

func TestParseSince_Days(t *testing.T) {
	before := time.Now().UTC()
	result, err := parseSince("3d")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	expected := before.AddDate(0, 0, -3)
	if result.Before(expected.Add(-time.Second)) || result.After(expected.Add(time.Second)) {
		t.Errorf("parseSince(3d) = %v, want ~%v", result, expected)
	}
}

func TestParseSince_Weeks(t *testing.T) {
	before := time.Now().UTC()
	result, err := parseSince("1w")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	expected := before.AddDate(0, 0, -7)
	if result.Before(expected.Add(-time.Second)) || result.After(expected.Add(time.Second)) {
		t.Errorf("parseSince(1w) = %v, want ~%v", result, expected)
	}
}

func TestParseSince_Months(t *testing.T) {
	before := time.Now().UTC()
	result, err := parseSince("2m")
	if err != nil {
		t.Fatalf("parseSince: %v", err)
	}
	expected := before.AddDate(0, -2, 0)
	if result.Before(expected.Add(-time.Second)) || result.After(expected.Add(time.Second)) {
		t.Errorf("parseSince(2m) = %v, want ~%v", result, expected)
	}
}

func TestParseSince_InvalidUnit(t *testing.T) {
	_, err := parseSince("5x")
	if err == nil || !strings.Contains(err.Error(), "invalid time unit") {
		t.Errorf("expected 'invalid time unit' error, got: %v", err)
	}
}

func TestParseSince_InvalidFormat(t *testing.T) {
	_, err := parseSince("abch")
	if err == nil || !strings.Contains(err.Error(), "invalid time value") {
		t.Errorf("expected 'invalid time value' error, got: %v", err)
	}
}

func TestParseSince_TooShort(t *testing.T) {
	_, err := parseSince("x")
	if err == nil {
		t.Error("expected error for single char input")
	}
}

// --- printAuditEntry ---

func TestPrintAuditEntry_Success(t *testing.T) {
	entry := &audit.AuditEntry{
		Timestamp:   time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Operation:   "exec",
		Command:     "claude",
		SecretNames: []string{"API_KEY", "DB_PASS"},
		AuthMethod:  "pin",
		Success:     true,
		User:        "testuser",
		Hostname:    "testhost",
		PID:         12345,
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printAuditEntry(entry, 1)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "[1]") {
		t.Errorf("output missing index: %q", output)
	}
	if !strings.Contains(output, "exec") {
		t.Errorf("output missing operation: %q", output)
	}
	if !strings.Contains(output, "claude") {
		t.Errorf("output missing command: %q", output)
	}
	if !strings.Contains(output, "API_KEY, DB_PASS") {
		t.Errorf("output missing secrets: %q", output)
	}
	if !strings.Contains(output, "pin") {
		t.Errorf("output missing auth method: %q", output)
	}
	if !strings.Contains(output, "testuser@testhost") {
		t.Errorf("output missing user info: %q", output)
	}
}

func TestPrintAuditEntry_Failure(t *testing.T) {
	entry := &audit.AuditEntry{
		Timestamp:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Operation:    "exec",
		Command:      "cmd",
		AuthMethod:   "none",
		Success:      false,
		User:         "user",
		Hostname:     "host",
		PID:          1,
		ErrorMessage: "something went wrong",
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printAuditEntry(entry, 2)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	r.Close()
	output := buf.String()

	if !strings.Contains(output, "something went wrong") {
		t.Errorf("output missing error: %q", output)
	}
}

// --- audit handlers ---

func TestRunAuditList_Disabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)

	output := captureStderr(t, func() {
		if err := runAuditList(nil, nil); err != nil {
			t.Fatalf("runAuditList: %v", err)
		}
	})
	if !strings.Contains(output, "not enabled") {
		t.Errorf("output = %q, want 'not enabled'", output)
	}
}

func TestRunAuditList_InvalidSince(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	oldSince := auditSince
	t.Cleanup(func() { auditSince = oldSince })
	auditSince = "invalid"

	err := runAuditList(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid since")
	}
}

func TestRunAuditExport_Disabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)

	err := runAuditExport(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' error, got: %v", err)
	}
}

func TestRunAuditExport_UnsupportedFormat(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	oldFormat := auditFormat
	oldSince := auditSince
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSince = oldSince
	})
	auditFormat = "xml"
	auditSince = ""

	err := runAuditExport(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected 'unsupported format' error, got: %v", err)
	}
}

func TestRunAuditClear_Disabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)

	err := runAuditClear(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' error, got: %v", err)
	}
}

func TestRunAuditClear_NoPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.RequireAuth = false
	withTestConfig(t, c)

	// Without a PIN, audit clear should proceed directly.
	output := captureStdout(t, func() {
		err := runAuditClear(nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	_ = output
}

func TestRunAuditClear_WithPIN(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	store.SetPINHash("test-hash")

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		if storedHash != "test-hash" {
			t.Errorf("authenticate received wrong hash: %q", storedHash)
		}
		return nil
	}

	output := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			err := runAuditClear(nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	})
	_ = output
}

// --- audit list / export with data ---

// seedAuditLog stores some audit entries into a mock keyring store via audit.Record.
func seedAuditLog(t *testing.T, store *nkeyring.Store, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		entry := &audit.AuditEntry{
			Timestamp:   time.Now().UTC(),
			Operation:   "exec",
			Command:     "test-cmd",
			SecretNames: []string{"KEY"},
			AuthMethod:  "none",
			Success:     true,
			User:        "testuser",
			Hostname:    "testhost",
			PID:         os.Getpid(),
		}
		if err := audit.Record(store, entry, 1000, 90); err != nil {
			t.Fatalf("audit.Record: %v", err)
		}
	}
}

func TestRunAuditList_WithEntries(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 3)

	oldSince := auditSince
	oldLimit := auditLimit
	t.Cleanup(func() {
		auditSince = oldSince
		auditLimit = oldLimit
	})
	auditSince = ""
	auditLimit = 0

	output := captureStdout(t, func() {
		if err := runAuditList(nil, nil); err != nil {
			t.Fatalf("runAuditList: %v", err)
		}
	})
	if !strings.Contains(output, "Audit Entries (3)") {
		t.Errorf("output = %q, want 'Audit Entries (3)'", output)
	}
	if !strings.Contains(output, "test-cmd") {
		t.Errorf("output missing command: %q", output)
	}
}

func TestRunAuditList_WithSince(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 2)

	oldSince := auditSince
	oldLimit := auditLimit
	t.Cleanup(func() {
		auditSince = oldSince
		auditLimit = oldLimit
	})
	auditSince = "1h"
	auditLimit = 0

	output := captureStdout(t, func() {
		if err := runAuditList(nil, nil); err != nil {
			t.Fatalf("runAuditList: %v", err)
		}
	})
	if !strings.Contains(output, "Audit Entries") {
		t.Errorf("output = %q, want entries", output)
	}
}

func TestRunAuditList_NoMatches(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 1)

	oldSince := auditSince
	oldCommand := auditCommand
	t.Cleanup(func() {
		auditSince = oldSince
		auditCommand = oldCommand
	})
	auditSince = ""
	auditCommand = "nonexistent-command"

	output := captureStdout(t, func() {
		if err := runAuditList(nil, nil); err != nil {
			t.Fatalf("runAuditList: %v", err)
		}
	})
	if !strings.Contains(output, "No audit entries found") {
		t.Errorf("output = %q, want 'No audit entries found'", output)
	}
}

func TestRunAuditExport_JSON(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 2)

	oldFormat := auditFormat
	oldSince := auditSince
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSince = oldSince
		auditOutput = oldOutput
	})
	auditFormat = "json"
	auditSince = ""
	auditOutput = "" // stdout

	output := captureStdout(t, func() {
		if err := runAuditExport(nil, nil); err != nil {
			t.Fatalf("runAuditExport: %v", err)
		}
	})
	if !strings.Contains(output, "test-cmd") {
		t.Errorf("JSON output missing command: %q", output)
	}
	if !strings.Contains(output, "[") {
		t.Errorf("JSON output should contain array bracket: %q", output)
	}
}

func TestRunAuditExport_CSV(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 1)

	oldFormat := auditFormat
	oldSince := auditSince
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSince = oldSince
		auditOutput = oldOutput
	})
	auditFormat = "csv"
	auditSince = ""
	auditOutput = ""

	output := captureStdout(t, func() {
		if err := runAuditExport(nil, nil); err != nil {
			t.Fatalf("runAuditExport: %v", err)
		}
	})
	if !strings.Contains(output, "test-cmd") {
		t.Errorf("CSV output missing command: %q", output)
	}
}

func TestRunAuditExport_ToFile(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 1)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "audit.json")

	oldFormat := auditFormat
	oldSince := auditSince
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSince = oldSince
		auditOutput = oldOutput
	})
	auditFormat = "json"
	auditSince = ""
	auditOutput = outFile

	output := captureStdout(t, func() {
		if err := runAuditExport(nil, nil); err != nil {
			t.Fatalf("runAuditExport: %v", err)
		}
	})
	if !strings.Contains(output, "Exported") {
		t.Errorf("output = %q, want export confirmation", output)
	}

	// Verify file was written
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "test-cmd") {
		t.Errorf("file content missing command: %q", string(data))
	}
}

func TestRunAuditExport_WithSince(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 1)

	oldFormat := auditFormat
	oldSince := auditSince
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSince = oldSince
		auditOutput = oldOutput
	})
	auditFormat = "json"
	auditSince = "1h"
	auditOutput = ""

	output := captureStdout(t, func() {
		if err := runAuditExport(nil, nil); err != nil {
			t.Fatalf("runAuditExport: %v", err)
		}
	})
	if !strings.Contains(output, "test-cmd") {
		t.Errorf("output missing command: %q", output)
	}
}

func TestRunAuditExport_InvalidSince(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	oldFormat := auditFormat
	oldSince := auditSince
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSince = oldSince
		auditOutput = oldOutput
	})
	auditFormat = "json"
	auditSince = "invalid"
	auditOutput = ""

	err := runAuditExport(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid since")
	}
}

func TestRunAuditClear_Success(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.RequireAuth = false
	withTestConfig(t, c)

	seedAuditLog(t, store, 3)

	output := captureStdout(t, func() {
		err := runAuditClear(nil, nil)
		if err != nil {
			t.Fatalf("runAuditClear: %v", err)
		}
	})
	if !strings.Contains(output, "cleared successfully") {
		t.Errorf("output = %q, want 'cleared successfully'", output)
	}
}

func TestRunAuditClear_WithAuth(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.RequireAuth = true
	withTestConfig(t, c)

	store.SetPINHash("some-hash")
	seedAuditLog(t, store, 2)

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		if storedHash != "some-hash" {
			t.Errorf("authenticate hash = %q, want 'some-hash'", storedHash)
		}
		return nil
	}

	output := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := runAuditClear(nil, nil); err != nil {
				t.Fatalf("runAuditClear with auth: %v", err)
			}
		})
	})
	if !strings.Contains(output, "cleared successfully") {
		t.Errorf("output = %q, want 'cleared successfully'", output)
	}
}

func TestRunAuditClear_WithAuthFailed(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.RequireAuth = true
	withTestConfig(t, c)

	store.SetPINHash("some-hash")
	seedAuditLog(t, store, 2)

	old := authAuthenticateFn
	t.Cleanup(func() { authAuthenticateFn = old })
	authAuthenticateFn = func(storedHash string) error {
		return fmt.Errorf("wrong pin")
	}

	_ = captureStderr(t, func() {
		err := runAuditClear(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "wrong pin") {
			t.Errorf("expected 'wrong pin' error, got: %v", err)
		}
	})
}

func TestRunAuditClear_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	err := runAuditClear(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

func TestRunAuditExport_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	err := runAuditExport(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

// --- audit list getKeyring error ---

func TestRunAuditList_GetKeyringError(t *testing.T) {
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring locked")
	}
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	err := runAuditList(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "keyring locked") {
		t.Errorf("expected 'keyring locked' error, got: %v", err)
	}
}

// --- audit clear with HasPIN but GetPINHash error ---

func TestRunAuditClear_HasPINGetHashError(t *testing.T) {
	// RequireAuth = true but no PIN hash stored → GetPINHash returns error
	store, _ := newTestStore()
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.RequireAuth = true
	withTestConfig(t, c)

	// Don't set a PIN hash → store.HasPIN() returns false but RequireAuth is true
	// So it enters the auth block and tries GetPINHash which fails
	err := runAuditClear(nil, nil)
	if err == nil {
		t.Fatal("expected error when RequireAuth=true but no PIN hash")
	}
}

// --- audit clear on empty state ---

func TestRunAuditClear_NoFilesNoPanic(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	c.RequireAuth = false
	withTestConfig(t, c)

	output := captureStdout(t, func() {
		err := runAuditClear(nil, nil)
		if err != nil {
			t.Fatalf("runAuditClear on empty: %v", err)
		}
	})
	if !strings.Contains(output, "cleared successfully") {
		t.Errorf("output = %q, want 'cleared successfully'", output)
	}
}

// --- audit export with since filter ---

func TestRunAuditExport_WithFilterOptions(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 3)

	oldFormat := auditFormat
	oldSecret := auditSecret
	oldCommand := auditCommand
	oldOp := auditOperation
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditSecret = oldSecret
		auditCommand = oldCommand
		auditOperation = oldOp
	})
	auditFormat = "csv"
	auditSecret = "nonexistent"
	auditCommand = ""
	auditOperation = ""

	output := captureStdout(t, func() {
		err := runAuditExport(nil, nil)
		if err != nil {
			t.Fatalf("runAuditExport: %v", err)
		}
	})
	// With a filter that matches nothing, CSV should still contain the header
	if output == "" {
		t.Error("expected some CSV output")
	}
}

// --- audit list load error ---

func TestRunAuditList_LoadError(t *testing.T) {
	// Use errorSetRing so getOrCreateEncryptionKey fails (Set of new key fails)
	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	err := runAuditList(nil, nil)
	if err == nil {
		t.Fatal("expected error when audit.Load fails")
	}
	if !strings.Contains(err.Error(), "failed to load audit log") {
		t.Errorf("error = %v, want 'failed to load audit log'", err)
	}
}

// --- audit export load error ---

func TestRunAuditExport_LoadError(t *testing.T) {
	ring := newMockRing()
	store := nkeyring.NewWithRing(&errorSetRing{mockRing: ring}, "nokey-test")
	withTestKeyring(t, store)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	oldFormat := auditFormat
	t.Cleanup(func() { auditFormat = oldFormat })
	auditFormat = "json"

	err := runAuditExport(nil, nil)
	if err == nil {
		t.Fatal("expected error when audit.Load fails")
	}
	if !strings.Contains(err.Error(), "failed to load audit log") {
		t.Errorf("error = %v, want 'failed to load audit log'", err)
	}
}

// --- audit export write to file ---

func TestRunAuditExport_WriteToFile(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 2)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "export.json")

	oldFormat := auditFormat
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditOutput = oldOutput
	})
	auditFormat = "json"
	auditOutput = outFile

	output := captureStdout(t, func() {
		err := runAuditExport(nil, nil)
		if err != nil {
			t.Fatalf("runAuditExport: %v", err)
		}
	})
	if !strings.Contains(output, "Exported") {
		t.Errorf("output = %q, want 'Exported'", output)
	}

	// Verify file was created
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported file is empty")
	}
}

// --- audit export write to invalid path ---

func TestRunAuditExport_WriteFileError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	seedAuditLog(t, store, 1)

	oldFormat := auditFormat
	oldOutput := auditOutput
	t.Cleanup(func() {
		auditFormat = oldFormat
		auditOutput = oldOutput
	})
	auditFormat = "json"
	auditOutput = "/nonexistent/path/export.json"

	err := runAuditExport(nil, nil)
	if err == nil {
		t.Fatal("expected error when writing to invalid path")
	}
	if !strings.Contains(err.Error(), "failed to write output file") {
		t.Errorf("error = %v, want 'failed to write output file'", err)
	}
}
