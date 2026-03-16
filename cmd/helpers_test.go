package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	kring "github.com/99designs/keyring"
	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/oauth"
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

// withTestKeyring overrides getKeyring to return the given store and restores it on cleanup.
func withTestKeyring(t *testing.T, store *nkeyring.Store) {
	t.Helper()
	old := getKeyring
	t.Cleanup(func() { getKeyring = old })
	getKeyring = func() (*nkeyring.Store, error) { return store, nil }
}

// withTestConfig overrides the global cfg and restores it on cleanup.
func withTestConfig(t *testing.T, c *config.Config) {
	t.Helper()
	old := cfg
	t.Cleanup(func() { cfg = old })
	cfg = c
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

// mockOAuthProvider implements oauth.Provider for testing.
type mockOAuthProvider struct {
	refreshFn  func(ctx context.Context, refreshToken string) (*oauth.Token, error)
	validateFn func(ctx context.Context, token *oauth.Token) error
}

func (m *mockOAuthProvider) GetAuthURL(state string) string { return "http://mock/auth" }
func (m *mockOAuthProvider) ExchangeCode(ctx context.Context, code string) (*oauth.Token, error) {
	return nil, nil
}
func (m *mockOAuthProvider) RefreshToken(ctx context.Context, refreshToken string) (*oauth.Token, error) {
	if m.refreshFn != nil {
		return m.refreshFn(ctx, refreshToken)
	}
	return nil, nil
}
func (m *mockOAuthProvider) ValidateToken(ctx context.Context, token *oauth.Token) error {
	if m.validateFn != nil {
		return m.validateFn(ctx, token)
	}
	return nil
}
func (m *mockOAuthProvider) GetProviderName() string { return "mock" }

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

// withMockOAuthProvider overrides newOAuthProviderFn to return the given mock and restores on cleanup.
func withMockOAuthProvider(t *testing.T, provider oauth.Provider) {
	t.Helper()
	old := newOAuthProviderFn
	t.Cleanup(func() { newOAuthProviderFn = old })
	newOAuthProviderFn = func(name string, creds *oauth.ClientCredentials, redirectURL string) oauth.Provider {
		return provider
	}
}

// withApprovalFn overrides approvalRequestFn and restores it on cleanup.
func withApprovalFn(t *testing.T, fn func(context.Context, approval.Requester, string, []string) error) {
	t.Helper()
	old := approvalRequestFn
	t.Cleanup(func() { approvalRequestFn = old })
	approvalRequestFn = fn
}

// withNoBrowser stubs browserOpenFn so tests don't open a real browser.
func withNoBrowser(t *testing.T) {
	t.Helper()
	old := browserOpenFn
	t.Cleanup(func() { browserOpenFn = old })
	browserOpenFn = func(url string) error { return nil }
}
