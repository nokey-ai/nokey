package keyring

import (
	"errors"
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
