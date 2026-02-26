package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubProvider implements OAuth for GitHub
type GitHubProvider struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	config       *oauth2.Config
}

// NewGitHubProvider creates a new GitHub OAuth provider
func NewGitHubProvider(clientID, clientSecret string, redirectURL string) *GitHubProvider {
	scopes := []string{"user:email"}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     github.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	return &GitHubProvider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		config:       config,
	}
}

// GetAuthURL returns the GitHub OAuth authorization URL
func (p *GitHubProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges the authorization code for an access token
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*Token, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return FromOAuth2Token(token, p.Scopes), nil
}

// RefreshToken refreshes an expired access token
func (p *GitHubProvider) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	tokenSource := p.config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return FromOAuth2Token(token, p.Scopes), nil
}

// ValidateToken validates the token by fetching user info
func (p *GitHubProvider) ValidateToken(ctx context.Context, token *Token) error {
	client := p.config.Client(ctx, token.ToOAuth2Token())

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token validation failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse user info to verify token works
	var user map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return fmt.Errorf("failed to parse user info: %w", err)
	}

	// Check if we got a login (username)
	if _, ok := user["login"]; !ok {
		return fmt.Errorf("invalid response from GitHub API")
	}

	return nil
}

// GetProviderName returns "github"
func (p *GitHubProvider) GetProviderName() string {
	return "github"
}
