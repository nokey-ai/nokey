package oauth

import (
	"testing"
	"time"

	"github.com/99designs/keyring"
	nokeyKeyring "github.com/nokey-ai/nokey/internal/keyring"
	"golang.org/x/oauth2"
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

// --- Key helpers ---

func TestGetTokenKey(t *testing.T) {
	key := GetTokenKey("github")
	if key != "__nokey_oauth_token_github__" {
		t.Errorf("GetTokenKey = %q, want %q", key, "__nokey_oauth_token_github__")
	}
}

func TestGetCredentialsKey(t *testing.T) {
	key := GetCredentialsKey("github")
	if key != "__nokey_oauth_creds_github__" {
		t.Errorf("GetCredentialsKey = %q, want %q", key, "__nokey_oauth_creds_github__")
	}
}

// --- Token.IsExpired ---

func TestToken_IsExpired_ZeroExpiry(t *testing.T) {
	tok := &Token{} // Zero expiry means never-expires.
	if tok.IsExpired() {
		t.Error("Token with zero expiry should not be expired")
	}
}

func TestToken_IsExpired_Future(t *testing.T) {
	tok := &Token{Expiry: time.Now().Add(10 * time.Minute)}
	if tok.IsExpired() {
		t.Error("Token expiring in the future should not be expired")
	}
}

func TestToken_IsExpired_Past(t *testing.T) {
	tok := &Token{Expiry: time.Now().Add(-1 * time.Minute)}
	if !tok.IsExpired() {
		t.Error("Token expiring in the past should be expired")
	}
}

func TestToken_IsExpired_WithinBuffer(t *testing.T) {
	// Token expiring in 20 seconds — within the 30-second safety buffer.
	tok := &Token{Expiry: time.Now().Add(20 * time.Second)}
	if !tok.IsExpired() {
		t.Error("Token expiring within the 30-second buffer should be considered expired")
	}
}

// --- Token conversion ---

func TestToken_ToOAuth2Token(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	tok := &Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
		Expiry:       expiry,
	}
	o2 := tok.ToOAuth2Token()
	if o2.AccessToken != "access" {
		t.Errorf("AccessToken = %q, want %q", o2.AccessToken, "access")
	}
	if o2.RefreshToken != "refresh" {
		t.Errorf("RefreshToken = %q, want %q", o2.RefreshToken, "refresh")
	}
	if o2.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", o2.TokenType, "Bearer")
	}
	if !o2.Expiry.Equal(expiry) {
		t.Errorf("Expiry = %v, want %v", o2.Expiry, expiry)
	}
}

func TestFromOAuth2Token(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	o2 := &oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
		Expiry:       expiry,
	}
	scopes := []string{"read:user", "repo"}
	tok := FromOAuth2Token(o2, scopes)
	if tok.AccessToken != "access" {
		t.Errorf("AccessToken = %q, want %q", tok.AccessToken, "access")
	}
	if len(tok.Scopes) != 2 || tok.Scopes[0] != "read:user" {
		t.Errorf("Scopes = %v, want %v", tok.Scopes, scopes)
	}
}

// --- Token store / load / delete ---

func TestSaveLoadToken(t *testing.T) {
	store := newTestStore()
	tok := &Token{
		AccessToken: "tok123",
		TokenType:   "Bearer",
		Scopes:      []string{"repo"},
	}

	if err := SaveToken(store, "github", tok); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	loaded, err := LoadToken(store, "github")
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded.AccessToken != "tok123" {
		t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, "tok123")
	}
	if len(loaded.Scopes) != 1 || loaded.Scopes[0] != "repo" {
		t.Errorf("Scopes = %v, want [repo]", loaded.Scopes)
	}
}

func TestLoadToken_NotFound(t *testing.T) {
	store := newTestStore()
	if _, err := LoadToken(store, "github"); err == nil {
		t.Error("LoadToken should error when no token is stored")
	}
}

func TestDeleteToken(t *testing.T) {
	store := newTestStore()
	tok := &Token{AccessToken: "tok123"}
	_ = SaveToken(store, "github", tok)

	if err := DeleteToken(store, "github"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if _, err := LoadToken(store, "github"); err == nil {
		t.Error("LoadToken after DeleteToken should return error")
	}
}

// --- Client credentials store / load / delete ---

func TestSaveLoadClientCredentials(t *testing.T) {
	store := newTestStore()
	creds := &ClientCredentials{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Scopes:       []string{"read:user"},
	}

	if err := SaveClientCredentials(store, "github", creds); err != nil {
		t.Fatalf("SaveClientCredentials: %v", err)
	}

	loaded, err := LoadClientCredentials(store, "github")
	if err != nil {
		t.Fatalf("LoadClientCredentials: %v", err)
	}
	if loaded.ClientID != "client-id" {
		t.Errorf("ClientID = %q, want %q", loaded.ClientID, "client-id")
	}
	if loaded.ClientSecret != "client-secret" {
		t.Errorf("ClientSecret = %q, want %q", loaded.ClientSecret, "client-secret")
	}
}

func TestLoadClientCredentials_NotFound(t *testing.T) {
	store := newTestStore()
	if _, err := LoadClientCredentials(store, "github"); err == nil {
		t.Error("LoadClientCredentials should error when nothing is stored")
	}
}

func TestDeleteClientCredentials(t *testing.T) {
	store := newTestStore()
	creds := &ClientCredentials{ClientID: "id", ClientSecret: "secret"}
	_ = SaveClientCredentials(store, "github", creds)

	if err := DeleteClientCredentials(store, "github"); err != nil {
		t.Fatalf("DeleteClientCredentials: %v", err)
	}
	if _, err := LoadClientCredentials(store, "github"); err == nil {
		t.Error("LoadClientCredentials after delete should return error")
	}
}
