package keyring

import (
	"errors"
	"fmt"
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
	return &Store{ring: newMockRing(), serviceName: "test"}
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

	// Set a key successfully
	_ = s.Set("MYKEY", "val")

	// Now make Get fail (but Keys still works)
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
