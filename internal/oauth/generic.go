package oauth

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// GenericProvider implements OAuth for custom providers
type GenericProvider struct {
	Name         string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	ClientID     string
	ClientSecret string
	Scopes       []string
	config       *oauth2.Config
}

// NewGenericProvider creates a new generic OAuth provider
func NewGenericProvider(name, authURL, tokenURL, userInfoURL, clientID, clientSecret string, scopes []string, redirectURL string) *GenericProvider {
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}

	return &GenericProvider{
		Name:         name,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		UserInfoURL:  userInfoURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		config:       config,
	}
}

// GetAuthURL returns the OAuth authorization URL
func (p *GenericProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges the authorization code for an access token
func (p *GenericProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return FromOAuth2Token(token, p.Scopes), nil
}

// RefreshToken refreshes an expired access token
func (p *GenericProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	tokenSource := p.config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return FromOAuth2Token(token, p.Scopes), nil
}

// ValidateToken validates the token by fetching user info (if UserInfoURL is set)
func (p *GenericProvider) ValidateToken(ctx context.Context, token *Token) error {
	if p.UserInfoURL == "" {
		// If no user info URL is configured, just check token isn't expired
		if token.IsExpired() {
			return fmt.Errorf("token is expired")
		}
		return nil
	}

	client := p.config.Client(ctx, token.ToOAuth2Token())

	resp, err := client.Get(p.UserInfoURL)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token validation failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetProviderName returns the custom provider name
func (p *GenericProvider) GetProviderName() string {
	if p.Name != "" {
		return p.Name
	}
	return "custom"
}
