package cmd

import (
	"fmt"
	"testing"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// errorKeysRing is a mock keyring.Keyring that fails on Keys().
// Used by exec_test.go to test GetAll error paths.
type errorKeysRing struct {
	mockRing *mockRing
}

func (e *errorKeysRing) Get(key string) (kring.Item, error) { return e.mockRing.Get(key) }
func (e *errorKeysRing) GetMetadata(key string) (kring.Metadata, error) {
	return e.mockRing.GetMetadata(key)
}
func (e *errorKeysRing) Set(item kring.Item) error { return e.mockRing.Set(item) }
func (e *errorKeysRing) Remove(key string) error   { return e.mockRing.Remove(key) }
func (e *errorKeysRing) Keys() ([]string, error)   { return nil, fmt.Errorf("keys failed") }

// --- recordAudit ---

func TestRecordAudit_Disabled(t *testing.T) {
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)

	// Should be a no-op -- no panic
	recordAudit("test-op", "test-cmd", "target", true, "")
}

func TestRecordAudit_Enabled(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestAuditDir(t)

	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)

	// Should not panic; may fail silently due to missing encryption key
	recordAudit("test-op", "test-cmd", "target", true, "")
}

func TestRecordAudit_NilConfig(t *testing.T) {
	oldCfg := cfg
	t.Cleanup(func() { cfg = oldCfg })
	cfg = nil

	// Should be a no-op -- no panic
	recordAudit("test-op", "test-cmd", "target", true, "")
}

func TestRecordAudit_GetKeyringError(t *testing.T) {
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)
	withTestAuditDir(t)

	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) {
		return nil, fmt.Errorf("keyring unavailable")
	}

	// Should silently return -- no panic
	recordAudit("test-op", "test-cmd", "target", true, "")
}
