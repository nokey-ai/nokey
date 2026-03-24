package audit

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	nokeyKeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// mockRing is an in-memory keyring.Keyring for testing.
type mockRing struct {
	items map[string]keyring.Item
}

func newMockRing() *mockRing {
	return &mockRing{items: make(map[string]keyring.Item)}
}

func (m *mockRing) Get(key string) (keyring.Item, error) {
	item, ok := m.items[key]
	if !ok {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}
	return item, nil
}

func (m *mockRing) GetMetadata(_ string) (keyring.Metadata, error) {
	return keyring.Metadata{}, keyring.ErrMetadataNotSupported
}

func (m *mockRing) Set(item keyring.Item) error {
	m.items[item.Key] = item
	return nil
}

func (m *mockRing) Remove(key string) error {
	if _, ok := m.items[key]; !ok {
		return keyring.ErrKeyNotFound
	}
	delete(m.items, key)
	return nil
}

func (m *mockRing) Keys() ([]string, error) {
	keys := make([]string, 0, len(m.items))
	for k := range m.items {
		keys = append(keys, k)
	}
	return keys, nil
}

func newTestStore() *nokeyKeyring.Store {
	return nokeyKeyring.NewWithRing(newMockRing(), "test")
}

// withTestAuditDir overrides AuditLogDir to use a temp directory.
func withTestAuditDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := AuditLogDir
	t.Cleanup(func() { AuditLogDir = old })
	AuditLogDir = func() (string, error) { return dir, nil }
	return dir
}

// --- Chain primitives ---

func TestDeriveHMACKey_Deterministic(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	k1 := deriveHMACKey(&key)
	k2 := deriveHMACKey(&key)
	if len(k1) != 32 {
		t.Fatalf("HMAC key length = %d, want 32", len(k1))
	}
	for i := range k1 {
		if k1[i] != k2[i] {
			t.Fatal("deriveHMACKey is not deterministic")
		}
	}
}

func TestComputeLineHMAC_Deterministic(t *testing.T) {
	hmacKey := []byte("test-key-32-bytes-padding-extra!")
	data := []byte("some ciphertext line")
	h1 := computeLineHMAC(hmacKey, data)
	h2 := computeLineHMAC(hmacKey, data)
	if h1 != h2 {
		t.Fatalf("computeLineHMAC not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("HMAC hex length = %d, want 64", len(h1))
	}
}

func TestLoadSaveChainHead_RoundTrip(t *testing.T) {
	store := newTestStore()
	head := &chainHead{HMAC: "abc123", Count: 42}
	if err := saveChainHead(store, head); err != nil {
		t.Fatalf("saveChainHead: %v", err)
	}
	loaded, err := loadChainHead(store)
	if err != nil {
		t.Fatalf("loadChainHead: %v", err)
	}
	if loaded.HMAC != head.HMAC || loaded.Count != head.Count {
		t.Errorf("loaded = %+v, want %+v", loaded, head)
	}
}

func TestLoadChainHead_NotFound_ReturnsZero(t *testing.T) {
	store := newTestStore()
	head, err := loadChainHead(store)
	if err != nil {
		t.Fatalf("loadChainHead: %v", err)
	}
	if head.HMAC != "" || head.Count != 0 {
		t.Errorf("expected zero chainHead, got %+v", head)
	}
}

func TestAuditLogPath(t *testing.T) {
	dir := withTestAuditDir(t)
	p, err := auditLogPath()
	if err != nil {
		t.Fatalf("auditLogPath: %v", err)
	}
	want := dir + "/audit.log"
	if p != want {
		t.Errorf("auditLogPath = %q, want %q", p, want)
	}
}

// --- NewAuditEntry ---

func TestNewAuditEntry_Fields(t *testing.T) {
	before := time.Now().UTC()
	e := NewAuditEntry("exec", "git status", "pin", []string{"API_KEY"}, true, "")
	after := time.Now().UTC()

	if e.Operation != "exec" {
		t.Errorf("Operation = %q, want %q", e.Operation, "exec")
	}
	if e.Command != "git status" {
		t.Errorf("Command = %q, want %q", e.Command, "git status")
	}
	if e.AuthMethod != "pin" {
		t.Errorf("AuthMethod = %q, want %q", e.AuthMethod, "pin")
	}
	if len(e.SecretNames) != 1 || e.SecretNames[0] != "API_KEY" {
		t.Errorf("SecretNames = %v, want [API_KEY]", e.SecretNames)
	}
	if !e.Success {
		t.Error("Success should be true")
	}
	if e.ErrorMessage != "" {
		t.Errorf("ErrorMessage = %q, want empty", e.ErrorMessage)
	}
	if e.Timestamp.Before(before) || e.Timestamp.After(after) {
		t.Error("Timestamp should be approximately now")
	}
	if e.User == "" {
		t.Error("User should not be empty")
	}
	if e.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
	if e.PID <= 0 {
		t.Errorf("PID should be positive, got %d", e.PID)
	}
}

func TestNewAuditEntry_Failure(t *testing.T) {
	e := NewAuditEntry("set", "", "none", nil, false, "permission denied")
	if e.Success {
		t.Error("Success should be false")
	}
	if e.ErrorMessage != "permission denied" {
		t.Errorf("ErrorMessage = %q, want %q", e.ErrorMessage, "permission denied")
	}
}

// --- ApplyRetentionPolicy ---

func TestApplyRetentionPolicy_CountLimit(t *testing.T) {
	log := &AuditLog{}
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		log.Entries = append(log.Entries, AuditEntry{
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}

	log.ApplyRetentionPolicy(3, 90)

	if len(log.Entries) != 3 {
		t.Errorf("expected 3 entries after count limit, got %d", len(log.Entries))
	}
	// Should keep the 3 most recent.
	if !log.Entries[2].Timestamp.Equal(now.Add(4 * time.Second)) {
		t.Error("should retain the most recent entries")
	}
}

func TestApplyRetentionPolicy_AgeLimit(t *testing.T) {
	log := &AuditLog{}
	now := time.Now().UTC()
	log.Entries = []AuditEntry{
		{Timestamp: now.AddDate(0, 0, -100)}, // too old
		{Timestamp: now.AddDate(0, 0, -50)},  // within 90 days
		{Timestamp: now},                     // recent
	}

	log.ApplyRetentionPolicy(1000, 90)

	if len(log.Entries) != 2 {
		t.Errorf("expected 2 entries after age limit, got %d", len(log.Entries))
	}
}

func TestApplyRetentionPolicy_Empty(t *testing.T) {
	log := &AuditLog{}
	log.ApplyRetentionPolicy(1000, 90) // Should not panic.
	if len(log.Entries) != 0 {
		t.Error("empty log should remain empty")
	}
}

// --- Filter ---

func makeEntries() []AuditEntry {
	now := time.Now().UTC()
	return []AuditEntry{
		{
			Timestamp:   now.Add(-2 * time.Hour),
			Operation:   "exec",
			Command:     "git push",
			SecretNames: []string{"GITHUB_TOKEN"},
			AuthMethod:  "pin",
			Success:     true,
		},
		{
			Timestamp:   now.Add(-1 * time.Hour),
			Operation:   "set",
			Command:     "",
			SecretNames: []string{"DB_PASS"},
			AuthMethod:  "pin",
			Success:     true,
		},
		{
			Timestamp:   now,
			Operation:   "exec",
			Command:     "npm run build",
			SecretNames: []string{"GITHUB_TOKEN", "NPM_TOKEN"},
			AuthMethod:  "pin",
			Success:     false,
		},
	}
}

func TestFilter_NoOptions(t *testing.T) {
	log := &AuditLog{Entries: makeEntries()}
	results := log.Filter(FilterOptions{})
	if len(results) != 3 {
		t.Errorf("Filter with no options should return all entries, got %d", len(results))
	}
	// Should be sorted most-recent-first.
	if results[0].Timestamp.Before(results[1].Timestamp) {
		t.Error("Filter should return entries sorted most-recent-first")
	}
}

func TestFilter_ByOperation(t *testing.T) {
	log := &AuditLog{Entries: makeEntries()}
	results := log.Filter(FilterOptions{Operation: "exec"})
	if len(results) != 2 {
		t.Errorf("expected 2 exec entries, got %d", len(results))
	}
}

func TestFilter_BySecretName(t *testing.T) {
	log := &AuditLog{Entries: makeEntries()}
	results := log.Filter(FilterOptions{SecretName: "GITHUB_TOKEN"})
	if len(results) != 2 {
		t.Errorf("expected 2 entries with GITHUB_TOKEN, got %d", len(results))
	}
}

func TestFilter_ByCommand(t *testing.T) {
	log := &AuditLog{Entries: makeEntries()}
	results := log.Filter(FilterOptions{Command: "git push"})
	if len(results) != 1 {
		t.Errorf("expected 1 entry for 'git push', got %d", len(results))
	}
}

func TestFilter_BySince(t *testing.T) {
	log := &AuditLog{Entries: makeEntries()}
	since := time.Now().UTC().Add(-90 * time.Minute)
	results := log.Filter(FilterOptions{Since: &since})
	// Only entries within the last 90 minutes (i.e., 1h ago and now).
	if len(results) != 2 {
		t.Errorf("expected 2 recent entries, got %d", len(results))
	}
}

func TestFilter_Limit(t *testing.T) {
	log := &AuditLog{Entries: makeEntries()}
	results := log.Filter(FilterOptions{Limit: 1})
	if len(results) != 1 {
		t.Errorf("expected 1 entry with limit=1, got %d", len(results))
	}
}

// --- ExportJSON ---

func TestExportJSON(t *testing.T) {
	log := &AuditLog{}
	entries := []AuditEntry{
		{Operation: "exec", Command: "cmd", Success: true},
	}
	out, err := log.ExportJSON(entries)
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if !strings.Contains(string(out), `"exec"`) {
		t.Errorf("ExportJSON output missing operation: %s", out)
	}
}

func TestExportJSON_Empty(t *testing.T) {
	log := &AuditLog{}
	out, err := log.ExportJSON(nil)
	if err != nil {
		t.Fatalf("ExportJSON(nil): %v", err)
	}
	if string(out) != "null" {
		t.Errorf("ExportJSON(nil) = %q, want %q", out, "null")
	}
}

// --- ExportCSV ---

func TestExportCSV_Header(t *testing.T) {
	log := &AuditLog{}
	out, err := log.ExportCSV(nil)
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	csv := string(out)
	if !strings.HasPrefix(csv, "Timestamp,") {
		t.Errorf("ExportCSV should start with header, got: %s", csv)
	}
}

func TestExportCSV_Row(t *testing.T) {
	log := &AuditLog{}
	now := time.Now().UTC()
	entries := []AuditEntry{{
		Timestamp:   now,
		Operation:   "exec",
		Command:     "git push",
		SecretNames: []string{"TOKEN"},
		AuthMethod:  "pin",
		Success:     true,
		User:        "alice",
		Hostname:    "host1",
		PID:         42,
	}}
	out, err := log.ExportCSV(entries)
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	csv := string(out)
	if !strings.Contains(csv, "git push") {
		t.Errorf("ExportCSV missing command: %s", csv)
	}
	if !strings.Contains(csv, "alice") {
		t.Errorf("ExportCSV missing user: %s", csv)
	}
}

func TestExportCSV_EscapesCommas(t *testing.T) {
	log := &AuditLog{}
	entries := []AuditEntry{{
		Command: "cmd with, comma",
		Success: true,
	}}
	out, err := log.ExportCSV(entries)
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if !strings.Contains(string(out), `"cmd with, comma"`) {
		t.Errorf("ExportCSV should quote fields with commas: %s", out)
	}
}

// --- encrypt / decrypt (unexported, tested within package) ---

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello, world!")

	encrypted, err := encrypt(plaintext, &key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := decrypt(encrypted, &key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypt = %q, want %q", decrypted, plaintext)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	var key [32]byte
	encrypted, _ := encrypt([]byte("secret"), &key)

	var wrongKey [32]byte
	wrongKey[0] = 1
	if _, err := decrypt(encrypted, &wrongKey); err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	var key [32]byte
	if _, err := decrypt([]byte("short"), &key); err == nil {
		t.Error("decrypt of too-short data should fail")
	}
}

// --- Load / Save / Record (with mock store) ---

func TestLoadSave_RoundTrip(t *testing.T) {
	store := newTestStore()

	// Load from empty store should return empty log.
	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load on empty store: %v", err)
	}
	if len(log.Entries) != 0 {
		t.Errorf("expected empty log, got %d entries", len(log.Entries))
	}

	// Add an entry and save.
	log.Entries = append(log.Entries, AuditEntry{
		Operation: "set",
		Command:   "test",
		Success:   true,
		Timestamp: time.Now().UTC(),
	})
	if err := log.Save(store); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load again and verify.
	log2, err := Load(store)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if len(log2.Entries) != 1 {
		t.Errorf("expected 1 entry after reload, got %d", len(log2.Entries))
	}
	if log2.Entries[0].Operation != "set" {
		t.Errorf("reloaded entry operation = %q, want %q", log2.Entries[0].Operation, "set")
	}
}

func TestRecord(t *testing.T) {
	store := newTestStore()
	entry := NewAuditEntry("exec", "ls", "pin", []string{"KEY"}, true, "")

	if err := Record(store, entry, 1000, 90); err != nil {
		t.Fatalf("Record: %v", err)
	}

	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load after Record: %v", err)
	}
	if len(log.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(log.Entries))
	}
}

func TestGetOrCreateEncryptionKey_CreatesNew(t *testing.T) {
	store := newTestStore()
	key, err := getOrCreateEncryptionKey(store)
	if err != nil {
		t.Fatalf("getOrCreateEncryptionKey: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	// Key should be stored and retrievable
	key2, err := getOrCreateEncryptionKey(store)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if *key != *key2 {
		t.Error("expected same key on second call")
	}
}

func TestGetOrCreateEncryptionKey_LegacyRaw32(t *testing.T) {
	store := newTestStore()
	// Store a legacy 32-byte raw key
	raw32 := strings.Repeat("A", 32)
	_ = store.Set(AuditEncryptionKeyKey, raw32)

	key, err := getOrCreateEncryptionKey(store)
	if err != nil {
		t.Fatalf("getOrCreateEncryptionKey: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	// Should have migrated to base64
	val, _ := store.Get(AuditEncryptionKeyKey)
	if val == raw32 {
		t.Error("expected key to be migrated to base64")
	}
}

func TestGetOrCreateEncryptionKey_InvalidLength(t *testing.T) {
	store := newTestStore()
	// Store an invalid key (not 32 bytes, not valid base64 of 32 bytes)
	_ = store.Set(AuditEncryptionKeyKey, "too-short")

	_, err := getOrCreateEncryptionKey(store)
	if err == nil {
		t.Error("expected error for invalid key length")
	}
}

func TestLoad_CorruptedAuditLog(t *testing.T) {
	store := newTestStore()
	// First create a valid encryption key
	key, err := getOrCreateEncryptionKey(store)
	if err != nil {
		t.Fatalf("getOrCreateEncryptionKey: %v", err)
	}
	// Store encrypted but invalid JSON
	encrypted, err := encrypt([]byte("not-json{{{"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	_ = store.Set(AuditLogKey, string(encrypted))

	_, err = Load(store)
	if err == nil {
		t.Error("expected error for corrupted JSON")
	}
	if !strings.Contains(err.Error(), "parse audit log") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

func TestLoad_DecryptionFailure(t *testing.T) {
	store := newTestStore()
	// Create encryption key
	_, _ = getOrCreateEncryptionKey(store)
	// Store garbage (not valid encrypted data but long enough to have a nonce)
	_ = store.Set(AuditLogKey, strings.Repeat("x", 50))

	_, err := Load(store)
	if err == nil {
		t.Error("expected error for decryption failure")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("error should mention decryption, got: %v", err)
	}
}

func TestRecord_MultipleEntries(t *testing.T) {
	store := newTestStore()
	for i := 0; i < 3; i++ {
		entry := NewAuditEntry("exec", fmt.Sprintf("cmd-%d", i), "pin", []string{"KEY"}, true, "")
		if err := Record(store, entry, 1000, 90); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(log.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(log.Entries))
	}
}

func TestRecord_CustomRetention(t *testing.T) {
	store := newTestStore()
	// Record 5 entries with a max of 3
	for i := 0; i < 5; i++ {
		entry := NewAuditEntry("exec", fmt.Sprintf("cmd-%d", i), "pin", []string{"KEY"}, true, "")
		if err := Record(store, entry, 3, 90); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(log.Entries) != 3 {
		t.Errorf("expected 3 entries after custom retention, got %d", len(log.Entries))
	}
}

func TestCsvEscape_Quotes(t *testing.T) {
	got := csvEscape(`say "hello"`)
	if !strings.Contains(got, `""hello""`) {
		t.Errorf("expected doubled quotes, got: %s", got)
	}
}

func TestCsvEscape_Newline(t *testing.T) {
	got := csvEscape("line1\nline2")
	if got[0] != '"' {
		t.Errorf("expected quoted output for string with newline, got: %s", got)
	}
}

func TestCsvEscape_NoSpecialChars(t *testing.T) {
	got := csvEscape("simple")
	if got != "simple" {
		t.Errorf("expected unchanged string, got: %s", got)
	}
}
