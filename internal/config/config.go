package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Enabled       bool `yaml:"enabled,omitempty"`
	MaxEntries    int  `yaml:"max_entries,omitempty"`
	RetentionDays int  `yaml:"retention_days,omitempty"`
}

// OAuthGitHubConfig contains GitHub OAuth configuration
type OAuthGitHubConfig struct {
	Enabled      bool   `yaml:"enabled,omitempty"`
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
}

// OAuthCustomConfig contains custom OAuth 2.0 provider configuration
type OAuthCustomConfig struct {
	Enabled      bool   `yaml:"enabled,omitempty"`
	ProviderName string `yaml:"provider_name,omitempty"`
	AuthURL      string `yaml:"auth_url,omitempty"`
	TokenURL     string `yaml:"token_url,omitempty"`
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
}

// OAuthConfig contains OAuth configuration for all providers
type OAuthConfig struct {
	GitHub OAuthGitHubConfig `yaml:"github,omitempty"`
	Custom OAuthCustomConfig `yaml:"custom,omitempty"`
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	DefaultMethod string      `yaml:"default_method,omitempty"`  // "pin", "oauth", "both", "none"
	SessionTTL    string      `yaml:"session_ttl,omitempty"`     // duration string, e.g. "15m" (default), max "8h"
	SkipConfirm   bool        `yaml:"skip_confirm,omitempty"`    // skip y/N confirmation prompt in exec
	AutoMintToken bool        `yaml:"auto_mint_token,omitempty"` // auto-mint session token on first MCP approval
	OAuth         OAuthConfig `yaml:"oauth,omitempty"`
}

// Config represents the nokey configuration
type Config struct {
	// DefaultBackend is the keyring backend to use by default
	DefaultBackend string `yaml:"default_backend,omitempty"`

	// RedactByDefault enables output redaction by default in exec mode
	RedactByDefault bool `yaml:"redact_by_default,omitempty"`

	// ServiceName is the custom service name for keyring entries
	ServiceName string `yaml:"service_name,omitempty"`

	// RequireAuth requires human authentication before accessing any secrets
	// DEPRECATED: Use Auth.DefaultMethod instead. Kept for backward compatibility.
	// This creates a zero-trust model where AI assistants cannot access secrets
	// without explicit human interaction (PIN/password entry)
	RequireAuth bool `yaml:"require_auth,omitempty"`

	// Audit contains audit logging configuration
	Audit AuditConfig `yaml:"audit,omitempty"`

	// Auth contains authentication configuration
	Auth AuthConfig `yaml:"auth,omitempty"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		DefaultBackend:  "", // Empty means use keyring's default
		RedactByDefault: false,
		ServiceName:     "nokey",
		RequireAuth:     false,
		Audit: AuditConfig{
			Enabled:       false,
			MaxEntries:    1000,
			RetentionDays: 90,
		},
		Auth: AuthConfig{
			DefaultMethod: "", // Empty means auto-detect (PIN if configured, else none)
		},
	}
}

// userHomeDirFn is the function used to get the user's home directory.
// Overridable for testing.
var userHomeDirFn = os.UserHomeDir

// ConfigDir returns the nokey configuration directory.
// On Windows it uses %APPDATA%\nokey; elsewhere ~/.config/nokey.
// Exported as a var so tests can override it.
var ConfigDir = func() (string, error) {
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			return filepath.Join(appData, "nokey"), nil
		}
	}
	homeDir, err := userHomeDirFn()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	return filepath.Join(homeDir, ".config", "nokey"), nil
}

// ConfigPath returns the path to the config file
func ConfigPath() (string, error) {
	configDir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "config.yaml"), nil
}

// Load reads the config file, or returns default config if it doesn't exist
func Load() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	// If config doesn't exist, return default
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// LoadStrict reads the config file like Load, but rejects unknown YAML keys.
// Use this for validation commands where typos should be caught.
func LoadStrict() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// Save writes the config to disk
func Save(cfg *Config) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(path)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Don't persist secrets — they belong in the keyring, not config.yaml
	saved := *cfg
	saved.Auth.OAuth.GitHub.ClientSecret = ""
	saved.Auth.OAuth.Custom.ClientSecret = ""

	data, err := yaml.Marshal(&saved)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
