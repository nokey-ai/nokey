package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/policy"
)

// --- mock keyring backend ---

type mockRing struct {
	items map[string]kring.Item
}

func newMockRing() *mockRing {
	return &mockRing{items: make(map[string]kring.Item)}
}

func (m *mockRing) Get(key string) (kring.Item, error) {
	item, ok := m.items[key]
	if !ok {
		return kring.Item{}, kring.ErrKeyNotFound
	}
	return item, nil
}

func (m *mockRing) GetMetadata(_ string) (kring.Metadata, error) {
	return kring.Metadata{}, kring.ErrMetadataNotSupported
}

func (m *mockRing) Set(item kring.Item) error {
	m.items[item.Key] = item
	return nil
}

func (m *mockRing) Remove(key string) error {
	if _, ok := m.items[key]; !ok {
		return kring.ErrKeyNotFound
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

// newTestStore creates a keyring.Store backed by an in-memory mock.
func newTestStore() (*nkeyring.Store, *mockRing) {
	ring := newMockRing()
	store := nkeyring.NewWithRing(ring, "nokey-test")
	return store, ring
}

// withTestAuditDir overrides audit.AuditLogDir to a temp directory and restores on cleanup.
// Also resets the audit encryption key cache to prevent cross-test pollution.
func withTestAuditDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := audit.AuditLogDir
	t.Cleanup(func() {
		audit.AuditLogDir = old
		audit.ResetEncKeyCache()
	})
	audit.AuditLogDir = func() (string, error) { return dir, nil }
	audit.ResetEncKeyCache()
	return dir
}

// withTestKeyring overrides getKeyring to return the given store and restores it on cleanup.
func withTestKeyring(t *testing.T, store *nkeyring.Store) {
	t.Helper()
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) { return store, nil }
}

// withTestConfig overrides the global cfg and restores it on cleanup.
// Also isolates config.ConfigDir to a fresh temp dir so any policy/config
// file reads during the test don't accidentally pick up the developer's
// real ~/.config/nokey contents.
func withTestConfig(t *testing.T, c *config.Config) {
	t.Helper()
	old := cfg
	oldDir := config.ConfigDir
	dir := t.TempDir()
	t.Cleanup(func() {
		cfg = old
		config.ConfigDir = oldDir
	})
	cfg = c
	config.ConfigDir = func() (string, error) { return dir, nil }
}

// captureStdout captures stdout writes during fn() and returns the captured text.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	r.Close()
	return buf.String()
}

// captureStderr captures stderr writes during fn() and returns the captured text.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	fn()

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)
	r.Close()
	return buf.String()
}

// withStdin replaces os.Stdin with a pipe, writes content to it, and restores on cleanup.
func withStdin(t *testing.T, content string) {
	t.Helper()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		w.Write([]byte(content))
		w.Close()
	}()
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		r.Close()
	})
}

// withExecGlobals saves and restores exec-related injectable vars (osExitFn, skipConfirm, authMethod).
// The caller is responsible for setting execRunFn or redactRunFn if needed.
func withExecGlobals(t *testing.T) {
	t.Helper()
	oldExec := execRunFn
	oldRedact := redactRunFn
	oldExit := osExitFn
	oldSkip := skipConfirm
	oldMethod := authMethod
	t.Cleanup(func() {
		execRunFn = oldExec
		redactRunFn = oldRedact
		osExitFn = oldExit
		skipConfirm = oldSkip
		authMethod = oldMethod
	})
}

// approveTestPolicy approves the policies.yaml in the config directory as
// it is now, as `nokey policy approve` would, in the test keyring. It
// installs a test keyring if the test has none. With no file it does
// nothing.
func approveTestPolicy(t *testing.T) *nkeyring.Store {
	t.Helper()
	store, err := getKeyring()
	if err != nil {
		store, _ = newTestStore()
		withTestKeyring(t, store)
	}
	approveTestPolicyIn(t, store)
	return store
}

func approveTestPolicyIn(t *testing.T, store *nkeyring.Store) {
	t.Helper()
	configDir, err := getConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(policy.Path(configDir))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetInternal(policy.DigestKey, policy.Digest(data)); err != nil {
		t.Fatal(err)
	}
}

// newCAKeyStore returns an empty test keyring for the proxy CA key.
func newCAKeyStore() *nkeyring.Store {
	store, _ := newTestStore()
	return store
}

// withProxyPolicy writes and approves a policies.yaml with one proxy rule
// in the config directory under HOME, and returns the test keyring.
func withProxyPolicy(t *testing.T) *nkeyring.Store {
	t.Helper()
	configDir, err := getConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policiesYAML := `proxy:
  rules:
    - hosts: ["api.example.com"]
      headers:
        Authorization: "Bearer $MY_SECRET"
`
	if err := os.WriteFile(policy.Path(configDir), []byte(policiesYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return approveTestPolicy(t)
}
