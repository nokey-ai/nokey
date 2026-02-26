package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	nokeyKeyring "github.com/nokey-ai/nokey/internal/keyring"
	"golang.org/x/oauth2"
)

// Token represents an OAuth 2.0 token
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time `json:"expiry"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// Provider interface for OAuth providers
type Provider interface {
	// GetAuthURL returns the OAuth authorization URL with state token
	GetAuthURL(state string) string

	// ExchangeCode exchanges authorization code for access token
	ExchangeCode(ctx context.Context, code string) (*Token, error)

	// RefreshToken refreshes an expired access token
	RefreshToken(ctx context.Context, refreshToken string) (*Token, error)

	// ValidateToken validates the token by making a test API call
	ValidateToken(ctx context.Context, token *Token) error

	// GetProviderName returns the name of the provider
	GetProviderName() string
}

// TokenKeyPrefix is the keyring prefix for OAuth tokens
const TokenKeyPrefix = "__nokey_oauth_token_" //nolint:gosec // Not a credential, just a keyring key prefix

// CredentialsKeyPrefix is the keyring prefix for OAuth client credentials
const CredentialsKeyPrefix = "__nokey_oauth_creds_" //nolint:gosec // Not a credential, just a keyring key prefix

// ClientCredentials stores OAuth client credentials for token refresh
type ClientCredentials struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url,omitempty"`     // For generic providers
	TokenURL     string   `json:"token_url,omitempty"`    // For generic providers
	UserInfoURL  string   `json:"userinfo_url,omitempty"` // For generic providers
	Scopes       []string `json:"scopes,omitempty"`       // For generic providers
}

// GetTokenKey returns the keyring key for a provider's token
func GetTokenKey(providerName string) string {
	return TokenKeyPrefix + providerName + "__"
}

// GetCredentialsKey returns the keyring key for a provider's client credentials
func GetCredentialsKey(providerName string) string {
	return CredentialsKeyPrefix + providerName + "__"
}

// LoadToken loads an OAuth token from the keyring
func LoadToken(store *nokeyKeyring.Store, providerName string) (*Token, error) {
	key := GetTokenKey(providerName)
	tokenJSON, err := store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("token not found for provider %s: %w", providerName, err)
	}

	var token Token
	if err := json.Unmarshal([]byte(tokenJSON), &token); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return &token, nil
}

// SaveToken saves an OAuth token to the keyring
func SaveToken(store *nokeyKeyring.Store, providerName string, token *Token) error {
	key := GetTokenKey(providerName)
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to serialize token: %w", err)
	}

	if err := store.Set(key, string(tokenJSON)); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// DeleteToken removes an OAuth token from the keyring
func DeleteToken(store *nokeyKeyring.Store, providerName string) error {
	key := GetTokenKey(providerName)
	if err := store.Delete(key); err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	return nil
}

// SaveClientCredentials saves OAuth client credentials to the keyring
func SaveClientCredentials(store *nokeyKeyring.Store, providerName string, creds *ClientCredentials) error {
	key := GetCredentialsKey(providerName)
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}

	if err := store.Set(key, string(credsJSON)); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	return nil
}

// LoadClientCredentials loads OAuth client credentials from the keyring
func LoadClientCredentials(store *nokeyKeyring.Store, providerName string) (*ClientCredentials, error) {
	key := GetCredentialsKey(providerName)
	credsJSON, err := store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("credentials not found for provider %s: %w", providerName, err)
	}

	var creds ClientCredentials
	if err := json.Unmarshal([]byte(credsJSON), &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return &creds, nil
}

// DeleteClientCredentials removes OAuth client credentials from the keyring
func DeleteClientCredentials(store *nokeyKeyring.Store, providerName string) error {
	key := GetCredentialsKey(providerName)
	if err := store.Delete(key); err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	return nil
}

// IsExpired checks if a token is expired
func (t *Token) IsExpired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	// Consider token expired 30 seconds before actual expiry for safety
	return time.Now().Add(30 * time.Second).After(t.Expiry)
}

// ToOAuth2Token converts our Token to oauth2.Token
func (t *Token) ToOAuth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Expiry:       t.Expiry,
	}
}

// FromOAuth2Token converts oauth2.Token to our Token
func FromOAuth2Token(t *oauth2.Token, scopes []string) *Token {
	return &Token{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		Expiry:       t.Expiry,
		Scopes:       scopes,
	}
}
