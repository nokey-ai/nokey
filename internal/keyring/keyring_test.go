package keyring

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/99designs/keyring"
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

func newTestStore() *Store {
	return NewWithRing(newMockRing(), "test")
}

func TestStore_SetGet(t *testing.T) {
	s := newTestStore()
	if err := s.Set("MY_KEY", "myvalue"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val, err := s.Get("MY_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "myvalue" {
		t.Errorf("Get = %q, want %q", val, "myvalue")
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	s := newTestStore()
	_, err := s.Get("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound should be true, got error: %v", err)
	}
}

func TestStore_EmptyKey(t *testing.T) {
	s := newTestStore()
	if err := s.Set("", "v"); err == nil {
		t.Error("Set with empty key should return error")
	}
	if _, err := s.Get(""); err == nil {
		t.Error("Get with empty key should return error")
	}
	if err := s.Delete(""); err == nil {
		t.Error("Delete with empty key should return error")
	}
}

func TestStore_Delete(t *testing.T) {
	s := newTestStore()
	if err := s.Set("K", "v"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete("K"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("K"); err == nil {
		t.Error("Get after Delete should return error")
	}
}

func TestStore_Delete_NotFound(t *testing.T) {
	s := newTestStore()
	if err := s.Delete("MISSING"); err == nil {
		t.Error("Delete of missing key should return error")
	}
}

func TestStore_List_FiltersInternal(t *testing.T) {
	s := newTestStore()
	_ = s.Set("API_KEY", "v1")
	_ = s.Set("DB_PASS", "v2")
	_ = s.Set("__nokey_internal", "hidden")

	keys, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("List returned %d keys, want 2: %v", len(keys), keys)
	}
	for _, k := range keys {
		if k == "__nokey_internal" {
			t.Error("List should filter out __nokey_-prefixed keys")
		}
	}
	// Should be sorted.
	if len(keys) == 2 && keys[0] > keys[1] {
		t.Errorf("List should return sorted keys, got %v", keys)
	}
}

func TestStore_GetAll(t *testing.T) {
	s := newTestStore()
	_ = s.Set("FOO", "bar")
	_ = s.Set("BAZ", "qux")

	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("GetAll returned %d items, want 2", len(all))
	}
	if all["FOO"] != "bar" || all["BAZ"] != "qux" {
		t.Errorf("GetAll returned unexpected values: %v", all)
	}
}

func TestStore_PIN_Lifecycle(t *testing.T) {
	s := newTestStore()

	if s.HasPIN() {
		t.Error("HasPIN should be false initially")
	}

	if err := s.SetPINHash("hashvalue"); err != nil {
		t.Fatalf("SetPINHash: %v", err)
	}
	if !s.HasPIN() {
		t.Error("HasPIN should be true after SetPINHash")
	}

	hash, err := s.GetPINHash()
	if err != nil {
		t.Fatalf("GetPINHash: %v", err)
	}
	if hash != "hashvalue" {
		t.Errorf("GetPINHash = %q, want %q", hash, "hashvalue")
	}

	if err := s.DeletePINHash(); err != nil {
		t.Fatalf("DeletePINHash: %v", err)
	}
	if s.HasPIN() {
		t.Error("HasPIN should be false after DeletePINHash")
	}
}

func TestStore_GetPINHash_NotSet(t *testing.T) {
	s := newTestStore()
	if _, err := s.GetPINHash(); err == nil {
		t.Error("GetPINHash should error when no PIN is set")
	}
}

func TestStore_DeletePINHash_NotSet(t *testing.T) {
	s := newTestStore()
	if err := s.DeletePINHash(); err == nil {
		t.Error("DeletePINHash should error when no PIN is set")
	}
}

// --- getFileBackendDir ---

func TestGetFileBackendDir(t *testing.T) {
	dir := getFileBackendDir()
	if dir == "" {
		t.Error("getFileBackendDir should return a non-empty path")
	}
	if !strings.Contains(dir, ".config/nokey") {
		t.Errorf("getFileBackendDir = %q, should contain .config/nokey", dir)
	}
}

// --- NewWithRing ---

func TestNewWithRing_DefaultServiceName(t *testing.T) {
	s := NewWithRing(newMockRing(), "")
	if s.serviceName != "nokey" {
		t.Errorf("serviceName = %q, want %q", s.serviceName, "nokey")
	}
}

func TestNewWithRing_CustomServiceName(t *testing.T) {
	s := NewWithRing(newMockRing(), "custom")
	if s.serviceName != "custom" {
		t.Errorf("serviceName = %q, want %q", s.serviceName, "custom")
	}
}

// --- AuthenticatedGetAll ---

func TestAuthenticatedGetAll_Success(t *testing.T) {
	s := newTestStore()
	_ = s.Set("KEY1", "val1")
	_ = s.Set("KEY2", "val2")
	_ = s.SetPINHash("somehash")

	oldAuth := authenticateFn
	defer func() { authenticateFn = oldAuth }()
	authenticateFn = func(hash string) error { return nil }

	secrets, err := s.AuthenticatedGetAll()
	if err != nil {
		t.Fatalf("AuthenticatedGetAll: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}
	if secrets["KEY1"] != "val1" {
		t.Errorf("KEY1 = %q, want %q", secrets["KEY1"], "val1")
	}
}

func TestAuthenticatedGetAll_AuthFails(t *testing.T) {
	s := newTestStore()
	_ = s.SetPINHash("somehash")

	oldAuth := authenticateFn
	defer func() { authenticateFn = oldAuth }()
	authenticateFn = func(hash string) error { return fmt.Errorf("auth failed") }

	_, err := s.AuthenticatedGetAll()
	if err == nil {
		t.Error("AuthenticatedGetAll should fail when auth fails")
	}
}

func TestAuthenticatedGetAll_NoPIN(t *testing.T) {
	s := newTestStore()

	_, err := s.AuthenticatedGetAll()
	if err == nil {
		t.Error("AuthenticatedGetAll should fail when no PIN configured")
	}
}

// --- Store edge cases ---

func TestStore_SetOverwrite(t *testing.T) {
	s := newTestStore()
	_ = s.Set("KEY", "v1")
	_ = s.Set("KEY", "v2")

	val, err := s.Get("KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if val != "v2" {
		t.Errorf("Get = %q, want %q", val, "v2")
	}
}

func TestStore_List_Empty(t *testing.T) {
	s := newTestStore()
	keys, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List on empty store should return 0 keys, got %d", len(keys))
	}
}

func TestStore_GetAll_Empty(t *testing.T) {
	s := newTestStore()
	all, err := s.GetAll()
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("GetAll on empty store should return 0 items, got %d", len(all))
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("secret not found: KEY"), true},
		{errors.New("secret not found:"), true},
		{errors.New("other error"), false},
		{errors.New("failed to retrieve: something"), false},
	}
	for _, tt := range tests {
		if got := IsNotFound(tt.err); got != tt.want {
			t.Errorf("IsNotFound(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

// --- Error-returning mock ---

// errorRing is a mock keyring that returns errors on demand.
type errorRing struct {
	mockRing
	setErr    error
	getErr    error
	removeErr error
	keysErr   error
}

func (m *errorRing) Set(item keyring.Item) error {
	if m.setErr != nil {
		return m.setErr
	}
	return m.mockRing.Set(item)
}

func (m *errorRing) Get(key string) (keyring.Item, error) {
	if m.getErr != nil {
		return keyring.Item{}, m.getErr
	}
	return m.mockRing.Get(key)
}

func (m *errorRing) Remove(key string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	return m.mockRing.Remove(key)
}

func (m *errorRing) Keys() ([]string, error) {
	if m.keysErr != nil {
		return nil, m.keysErr
	}
	return m.mockRing.Keys()
}

// --- Ring error tests ---

func TestStore_Set_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), setErr: errors.New("ring write failed")}
	s := NewWithRing(ring, "test")
	err := s.Set("KEY", "val")
	if err == nil {
		t.Error("expected error from ring")
	}
	if !strings.Contains(err.Error(), "failed to store") {
		t.Errorf("error = %v, want 'failed to store' prefix", err)
	}
}

func TestStore_Get_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), getErr: errors.New("ring read failed")}
	s := NewWithRing(ring, "test")
	_, err := s.Get("KEY")
	if err == nil {
		t.Error("expected error from ring")
	}
	if !strings.Contains(err.Error(), "failed to retrieve") {
		t.Errorf("error = %v, want 'failed to retrieve' prefix", err)
	}
}

func TestStore_Delete_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), removeErr: errors.New("ring remove failed")}
	s := NewWithRing(ring, "test")
	// Set first so it exists
	ring.removeErr = nil
	_ = s.Set("KEY", "val")
	ring.removeErr = errors.New("ring remove failed")
	err := s.Delete("KEY")
	if err == nil {
		t.Error("expected error from ring")
	}
	if !strings.Contains(err.Error(), "failed to delete") {
		t.Errorf("error = %v, want 'failed to delete' prefix", err)
	}
}

func TestStore_List_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), keysErr: errors.New("ring keys failed")}
	s := NewWithRing(ring, "test")
	_, err := s.List()
	if err == nil {
		t.Error("expected error from ring")
	}
	if !strings.Contains(err.Error(), "failed to list") {
		t.Errorf("error = %v, want 'failed to list' prefix", err)
	}
}

func TestStore_GetAll_ListError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), keysErr: errors.New("ring keys failed")}
	s := NewWithRing(ring, "test")
	_, err := s.GetAll()
	if err == nil {
		t.Error("expected error when GetAll fails")
	}
}

func TestStore_GetPINHash_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), getErr: errors.New("ring failed")}
	s := NewWithRing(ring, "test")
	_, err := s.GetPINHash()
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "failed to retrieve PIN") {
		t.Errorf("error = %v, want 'failed to retrieve PIN' prefix", err)
	}
}

func TestStore_SetPINHash_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), setErr: errors.New("ring failed")}
	s := NewWithRing(ring, "test")
	err := s.SetPINHash("hash")
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "failed to store PIN") {
		t.Errorf("error = %v, want 'failed to store PIN' prefix", err)
	}
}

func TestStore_DeletePINHash_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), removeErr: errors.New("ring failed")}
	s := NewWithRing(ring, "test")
	// First set the PIN hash successfully
	ring.removeErr = nil
	_ = s.SetPINHash("hash")
	ring.removeErr = errors.New("ring failed")
	err := s.DeletePINHash()
	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "failed to delete PIN") {
		t.Errorf("error = %v, want 'failed to delete PIN' prefix", err)
	}
}

func TestStore_HasPIN_RingError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), getErr: errors.New("ring failed")}
	s := NewWithRing(ring, "test")
	if s.HasPIN() {
		t.Error("HasPIN should return false when ring errors")
	}
}

func TestStore_GetAll_GetError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")

	// Insert a key directly into the ring (bypassing cache)
	ring.items["MYKEY"] = keyring.Item{Key: "MYKEY", Data: []byte("val")}

	// Make Get fail — the key exists in ring.Keys() but ring.Get() errors
	ring.getErr = errors.New("ring get failed")

	_, err := s.GetAll()
	if err == nil {
		t.Error("expected error when individual Get fails in GetAll")
	}
}

// --- New() tests via injectable keyringOpenFn ---

func TestNew_DefaultBackend(t *testing.T) {
	old := keyringOpenFn
	defer func() { keyringOpenFn = old }()
	keyringOpenFn = func(config keyring.Config) (keyring.Keyring, error) {
		if config.AllowedBackends != nil {
			t.Errorf("AllowedBackends should be nil for default backend, got %v", config.AllowedBackends)
		}
		return newMockRing(), nil
	}

	s, err := New("", "myservice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.serviceName != "myservice" {
		t.Errorf("serviceName = %q, want %q", s.serviceName, "myservice")
	}
}

func TestNew_SpecificBackend(t *testing.T) {
	old := keyringOpenFn
	defer func() { keyringOpenFn = old }()
	keyringOpenFn = func(config keyring.Config) (keyring.Keyring, error) {
		if len(config.AllowedBackends) != 1 || config.AllowedBackends[0] != "file" {
			t.Errorf("AllowedBackends = %v, want [file]", config.AllowedBackends)
		}
		return newMockRing(), nil
	}

	s, err := New("file", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.serviceName != "nokey" {
		t.Errorf("serviceName = %q, want default %q", s.serviceName, "nokey")
	}
}

func TestNew_OpenError(t *testing.T) {
	old := keyringOpenFn
	defer func() { keyringOpenFn = old }()
	keyringOpenFn = func(config keyring.Config) (keyring.Keyring, error) {
		return nil, fmt.Errorf("keyring unavailable")
	}

	_, err := New("", "test")
	if err == nil {
		t.Fatal("New should fail when keyring.Open fails")
	}
	if !strings.Contains(err.Error(), "failed to open keyring") {
		t.Errorf("error = %v, want 'failed to open keyring'", err)
	}
}

func TestNew_DefaultServiceName(t *testing.T) {
	old := keyringOpenFn
	defer func() { keyringOpenFn = old }()
	keyringOpenFn = func(config keyring.Config) (keyring.Keyring, error) {
		if config.ServiceName != "nokey" {
			t.Errorf("ServiceName = %q, want %q", config.ServiceName, "nokey")
		}
		return newMockRing(), nil
	}

	s, err := New("", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.serviceName != "nokey" {
		t.Errorf("serviceName = %q, want %q", s.serviceName, "nokey")
	}
}

func TestAuthenticatedGetAll_GetAllError(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")

	// Set up PIN hash successfully
	_ = s.SetPINHash("somehash")

	oldAuth := authenticateFn
	defer func() { authenticateFn = oldAuth }()
	authenticateFn = func(hash string) error { return nil }

	// Now make Keys fail
	ring.keysErr = errors.New("keys failed")
	_, err := s.AuthenticatedGetAll()
	if err == nil {
		t.Error("expected error when GetAll fails")
	}
}

// --- Cache behavior tests ---

func TestStore_Cache_GetServedFromCache(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")

	// Set populates cache
	_ = s.Set("KEY", "val")

	// Make ring.Get fail — should still return from cache
	ring.getErr = errors.New("ring broken")
	val, err := s.Get("KEY")
	if err != nil {
		t.Fatalf("Get should serve from cache: %v", err)
	}
	if val != "val" {
		t.Errorf("Get = %q, want %q", val, "val")
	}
}

func TestStore_Cache_DeleteEvictsCache(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")

	_ = s.Set("KEY", "val")
	_ = s.Delete("KEY")

	// After delete, cache should be evicted; ring.Get returns not found
	_, err := s.Get("KEY")
	if err == nil {
		t.Error("Get after Delete should fail")
	}
}

func TestStore_Cache_SetOverwritesCache(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")

	_ = s.Set("KEY", "v1")
	_ = s.Set("KEY", "v2")

	// Make ring fail to prove we're reading from cache
	ring.getErr = errors.New("ring broken")
	val, err := s.Get("KEY")
	if err != nil {
		t.Fatalf("Get should serve from cache: %v", err)
	}
	if val != "v2" {
		t.Errorf("Get = %q, want %q", val, "v2")
	}
}

func TestStore_Cache_GetPopulatesCache(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")

	// Insert directly into ring, bypassing cache
	ring.items["KEY"] = keyring.Item{Key: "KEY", Data: []byte("val")}

	// First Get populates cache
	_, err := s.Get("KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Now break ring — second Get should still work from cache
	ring.getErr = errors.New("ring broken")
	val, err := s.Get("KEY")
	if err != nil {
		t.Fatalf("cached Get: %v", err)
	}
	if val != "val" {
		t.Errorf("Get = %q, want %q", val, "val")
	}
}

// --- AllKeys tests ---

func TestStore_AllKeys_IncludesInternal(t *testing.T) {
	s := newTestStore()
	_ = s.Set("API_KEY", "v1")
	_ = s.Set("__nokey_internal", "hidden")

	keys, err := s.AllKeys()
	if err != nil {
		t.Fatalf("AllKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("AllKeys returned %d keys, want 2: %v", len(keys), keys)
	}
	found := false
	for _, k := range keys {
		if k == "__nokey_internal" {
			found = true
		}
	}
	if !found {
		t.Error("AllKeys should include __nokey_-prefixed keys")
	}
}

func TestStore_AllKeys_Sorted(t *testing.T) {
	s := newTestStore()
	_ = s.Set("Z_KEY", "v")
	_ = s.Set("A_KEY", "v")
	_ = s.Set("M_KEY", "v")

	keys, err := s.AllKeys()
	if err != nil {
		t.Fatalf("AllKeys: %v", err)
	}
	for i := 1; i < len(keys); i++ {
		if keys[i-1] > keys[i] {
			t.Errorf("AllKeys not sorted: %v", keys)
			break
		}
	}
}

func TestStore_AllKeys_Error(t *testing.T) {
	ring := &errorRing{mockRing: *newMockRing(), keysErr: errors.New("keys failed")}
	s := NewWithRing(ring, "test")
	_, err := s.AllKeys()
	if err == nil {
		t.Error("AllKeys should return error when ring.Keys fails")
	}
}

// --- MigrateAllItems tests ---

func TestStore_MigrateAllItems_DryRun(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("MigrateAllItems is macOS-only")
	}
	s := newTestStore()
	_ = s.Set("KEY1", "v1")
	_ = s.Set("KEY2", "v2")

	count, err := s.MigrateAllItems(true)
	if err != nil {
		t.Fatalf("MigrateAllItems dry-run: %v", err)
	}
	if count != 2 {
		t.Errorf("dry-run count = %d, want 2", count)
	}

	// Verify data is unchanged
	v, _ := s.Get("KEY1")
	if v != "v1" {
		t.Errorf("KEY1 = %q after dry-run, want %q", v, "v1")
	}
}

func TestStore_MigrateAllItems_Migrate(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("MigrateAllItems is macOS-only")
	}
	s := newTestStore()
	_ = s.Set("KEY1", "v1")
	_ = s.Set("__nokey_pin", "pinhash")

	count, err := s.MigrateAllItems(false)
	if err != nil {
		t.Fatalf("MigrateAllItems: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}

	// Verify data preserved
	v1, _ := s.Get("KEY1")
	if v1 != "v1" {
		t.Errorf("KEY1 = %q after migrate, want %q", v1, "v1")
	}
	v2, _ := s.Get("__nokey_pin")
	if v2 != "pinhash" {
		t.Errorf("__nokey_pin = %q after migrate, want %q", v2, "pinhash")
	}
}

func TestStore_MigrateAllItems_Empty(t *testing.T) {
	s := newTestStore()
	count, err := s.MigrateAllItems(false)
	if err != nil {
		t.Fatalf("MigrateAllItems: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestStore_MigrateAllItems_KeysError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("MigrateAllItems is macOS-only")
	}
	ring := &errorRing{mockRing: *newMockRing(), keysErr: errors.New("keys failed")}
	s := NewWithRing(ring, "test")
	_, err := s.MigrateAllItems(false)
	if err == nil {
		t.Error("MigrateAllItems should fail when Keys() errors")
	}
}

func TestStore_MigrateAllItems_GetError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("MigrateAllItems is macOS-only")
	}
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")
	// Insert directly to bypass cache
	ring.items["KEY"] = keyring.Item{Key: "KEY", Data: []byte("val")}
	ring.getErr = errors.New("get failed")

	_, err := s.MigrateAllItems(false)
	if err == nil {
		t.Error("MigrateAllItems should fail when Get() errors")
	}
}

func TestStore_MigrateAllItems_RemoveError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("MigrateAllItems is macOS-only")
	}
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")
	_ = s.Set("KEY", "val")
	ring.removeErr = errors.New("remove failed")

	_, err := s.MigrateAllItems(false)
	if err == nil {
		t.Error("MigrateAllItems should fail when Remove() errors")
	}
}

func TestStore_MigrateAllItems_SetError(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("MigrateAllItems is macOS-only")
	}
	ring := &errorRing{mockRing: *newMockRing()}
	s := NewWithRing(ring, "test")
	_ = s.Set("KEY", "val")
	// Remove will succeed (items exist), but Set will fail
	ring.setErr = errors.New("set failed")

	_, err := s.MigrateAllItems(false)
	if err == nil {
		t.Error("MigrateAllItems should fail when Set() errors")
	}
}

// --- ValidateSecretName ---

func TestValidateSecretName_Valid(t *testing.T) {
	valid := []string{"API_KEY", "my-secret", "a", "A1_B2.c3-d4", "UPPER_CASE_123"}
	for _, name := range valid {
		if err := ValidateSecretName(name); err != nil {
			t.Errorf("ValidateSecretName(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateSecretName_Invalid(t *testing.T) {
	cases := []struct {
		name string
		desc string
	}{
		{"", "empty"},
		{strings.Repeat("a", 129), "too long"},
		{"__nokey_internal", "reserved prefix"},
		{".dotfirst", "starts with dot"},
		{"-dashfirst", "starts with dash"},
		{"has space", "contains space"},
		{"has/slash", "contains slash"},
		{"has@at", "contains at sign"},
	}
	for _, tc := range cases {
		if err := ValidateSecretName(tc.name); err == nil {
			t.Errorf("ValidateSecretName(%q) [%s] = nil, want error", tc.name, tc.desc)
		}
	}
}

func TestStore_Set_RejectsInvalidName(t *testing.T) {
	s := newTestStore()
	if err := s.Set("has space", "val"); err == nil {
		t.Error("Set should reject invalid secret name")
	}
}

func TestStore_Set_AllowsInternalKeys(t *testing.T) {
	s := newTestStore()
	// Internal __nokey_ keys bypass validation (used by auth, audit, etc.)
	if err := s.Set("__nokey_internal_key", "val"); err != nil {
		t.Fatalf("Set should allow internal __nokey_ keys: %v", err)
	}
}

func TestStore_Set_AllowsDotsAndDashes(t *testing.T) {
	s := newTestStore()
	if err := s.Set("my.secret-key", "val"); err != nil {
		t.Fatalf("Set should allow dots and dashes: %v", err)
	}
	v, err := s.Get("my.secret-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v != "val" {
		t.Errorf("Get = %q, want %q", v, "val")
	}
}

// --- Trust flag test ---

func TestNew_KeychainTrustEnabled(t *testing.T) {
	old := keyringOpenFn
	defer func() { keyringOpenFn = old }()
	keyringOpenFn = func(config keyring.Config) (keyring.Keyring, error) {
		if !config.KeychainTrustApplication {
			t.Error("KeychainTrustApplication should be true")
		}
		return newMockRing(), nil
	}

	_, err := New("", "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}
