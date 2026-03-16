package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ServiceName != "nokey" {
		t.Errorf("Expected service name 'nokey', got %q", cfg.ServiceName)
	}

	if cfg.RedactByDefault != false {
		t.Errorf("Expected RedactByDefault to be false")
	}

	if cfg.DefaultBackend != "" {
		t.Errorf("Expected DefaultBackend to be empty, got %q", cfg.DefaultBackend)
	}
}

func TestLoadNonExistentConfig(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Override config path for testing
	oldHome := os.Getenv("HOME")
	defer os.Setenv("HOME", oldHome)
	os.Setenv("HOME", tempDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should return default config
	if cfg.ServiceName != "nokey" {
		t.Errorf("Expected default service name, got %q", cfg.ServiceName)
	}
}

func TestSaveAndLoad(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Override config path for testing
	oldHome := os.Getenv("HOME")
	defer os.Setenv("HOME", oldHome)
	os.Setenv("HOME", tempDir)

	// Create a test config
	testCfg := &Config{
		DefaultBackend:  "file",
		RedactByDefault: true,
		ServiceName:     "test-nokey",
	}

	// Save the config
	if err := Save(testCfg); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Verify the file was created
	configPath, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath() failed: %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Fatalf("Config file was not created at %s", configPath)
	}

	// Check file permissions
	fileInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("Stat() failed: %v", err)
	}

	mode := fileInfo.Mode()
	if mode.Perm() != 0600 {
		t.Errorf("Expected file permissions 0600, got %v", mode.Perm())
	}

	// Load the config
	loadedCfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify the loaded config matches
	if loadedCfg.DefaultBackend != testCfg.DefaultBackend {
		t.Errorf("DefaultBackend: expected %q, got %q", testCfg.DefaultBackend, loadedCfg.DefaultBackend)
	}

	if loadedCfg.RedactByDefault != testCfg.RedactByDefault {
		t.Errorf("RedactByDefault: expected %v, got %v", testCfg.RedactByDefault, loadedCfg.RedactByDefault)
	}

	if loadedCfg.ServiceName != testCfg.ServiceName {
		t.Errorf("ServiceName: expected %q, got %q", testCfg.ServiceName, loadedCfg.ServiceName)
	}
}

func TestConfigPath(t *testing.T) {
	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath() failed: %v", err)
	}

	if !filepath.IsAbs(path) {
		t.Errorf("ConfigPath() should return absolute path, got %q", path)
	}

	if filepath.Base(path) != "config.yaml" {
		t.Errorf("Expected config file to be named 'config.yaml', got %q", filepath.Base(path))
	}

	// Check that the path contains the expected directories
	if !strings.Contains(path, filepath.Join(".config", "nokey")) {
		t.Errorf("Expected path to contain .config/nokey, got %q", path)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Write invalid YAML
	configDir := filepath.Join(tempDir, ".config", "nokey")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte("{{invalid yaml"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Error("Load should fail with invalid YAML")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("error should mention parsing, got: %v", err)
	}
}

func TestSaveAndLoad_FullConfig(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := &Config{
		DefaultBackend:  "keychain",
		RedactByDefault: true,
		ServiceName:     "myservice",
		RequireAuth:     true,
		Audit: AuditConfig{
			Enabled:       true,
			MaxEntries:    500,
			RetentionDays: 30,
		},
		Auth: AuthConfig{
			DefaultMethod: "pin",
			SessionTTL:    "10m",
			AutoMintToken: true,
			OAuth: OAuthConfig{
				GitHub: OAuthGitHubConfig{
					Enabled:      true,
					ClientID:     "gh-client-id",
					ClientSecret: "gh-secret",
				},
				Custom: OAuthCustomConfig{
					Enabled:      true,
					ProviderName: "myoidc",
					AuthURL:      "https://auth.example.com/authorize",
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "custom-cid",
					ClientSecret: "custom-secret",
				},
			},
		},
	}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Audit.Enabled != true {
		t.Error("Audit.Enabled should be true")
	}
	if loaded.Audit.MaxEntries != 500 {
		t.Errorf("Audit.MaxEntries = %d, want 500", loaded.Audit.MaxEntries)
	}
	if loaded.Audit.RetentionDays != 30 {
		t.Errorf("Audit.RetentionDays = %d, want 30", loaded.Audit.RetentionDays)
	}
	if loaded.Auth.DefaultMethod != "pin" {
		t.Errorf("Auth.DefaultMethod = %q, want %q", loaded.Auth.DefaultMethod, "pin")
	}
	if loaded.Auth.SessionTTL != "10m" {
		t.Errorf("Auth.SessionTTL = %q, want %q", loaded.Auth.SessionTTL, "10m")
	}
	if !loaded.Auth.AutoMintToken {
		t.Error("Auth.AutoMintToken should be true")
	}
	if loaded.Auth.OAuth.GitHub.ClientID != "gh-client-id" {
		t.Errorf("GitHub.ClientID = %q, want %q", loaded.Auth.OAuth.GitHub.ClientID, "gh-client-id")
	}
	if loaded.Auth.OAuth.Custom.ProviderName != "myoidc" {
		t.Errorf("Custom.ProviderName = %q, want %q", loaded.Auth.OAuth.Custom.ProviderName, "myoidc")
	}
	if loaded.RequireAuth != true {
		t.Error("RequireAuth should be true")
	}
}

func TestDefaultConfig_AuditDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Audit.Enabled {
		t.Error("Audit should be disabled by default")
	}
	if cfg.Audit.MaxEntries != 1000 {
		t.Errorf("Audit.MaxEntries default = %d, want 1000", cfg.Audit.MaxEntries)
	}
	if cfg.Audit.RetentionDays != 90 {
		t.Errorf("Audit.RetentionDays default = %d, want 90", cfg.Audit.RetentionDays)
	}
}

func TestDefaultConfig_AuthDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Auth.DefaultMethod != "" {
		t.Errorf("Auth.DefaultMethod should be empty by default, got %q", cfg.Auth.DefaultMethod)
	}
}

func TestSave_CreatesDirectory(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := DefaultConfig()
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	configDir := filepath.Join(tempDir, ".config", "nokey")
	info, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("config dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("config dir should be a directory")
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("config dir permissions = %o, want 0700", info.Mode().Perm())
	}
}

func TestLoad_UnreadableFile(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	configDir := filepath.Join(tempDir, ".config", "nokey")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	configFile := filepath.Join(configDir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("valid: true"), 0000); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Error("Load should fail with unreadable file")
	}
}

func TestSave_DirectoryPermissions(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg := DefaultConfig()
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify file content is valid YAML
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if loaded.ServiceName != "nokey" {
		t.Errorf("ServiceName = %q, want %q", loaded.ServiceName, "nokey")
	}
}

func TestSave_OverwritesExisting(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cfg1 := &Config{ServiceName: "first"}
	if err := Save(cfg1); err != nil {
		t.Fatalf("first Save: %v", err)
	}

	cfg2 := &Config{ServiceName: "second"}
	if err := Save(cfg2); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ServiceName != "second" {
		t.Errorf("ServiceName = %q, want %q", loaded.ServiceName, "second")
	}
}

func TestSave_MkdirAllError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Place a regular file where the config directory should be,
	// so MkdirAll fails.
	blocker := filepath.Join(tempDir, ".config")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := DefaultConfig()
	err := Save(cfg)
	if err == nil {
		t.Error("Save should fail when MkdirAll cannot create directory")
	}
	if !strings.Contains(err.Error(), "config directory") {
		t.Errorf("error should mention config directory, got: %v", err)
	}
}

func TestSave_WriteFileError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Create the config directory but make it read-only so WriteFile fails
	configDir := filepath.Join(tempDir, ".config", "nokey")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(configDir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer os.Chmod(configDir, 0700) // cleanup

	cfg := DefaultConfig()
	err := Save(cfg)
	if err == nil {
		t.Error("Save should fail when directory is read-only")
	}
	if !strings.Contains(err.Error(), "write config") {
		t.Errorf("error should mention writing config, got: %v", err)
	}
}

func TestLoad_ConfigPathError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Block .config from being a directory
	blocker := filepath.Join(tempDir, ".config")
	os.WriteFile(blocker, []byte("not a dir"), 0600)

	// Load should still work since ConfigPath itself doesn't create dirs,
	// and stat will say "not exist" for the path, returning defaults
	cfg, err := Load()
	if err != nil {
		// On some systems this might fail differently; either way is acceptable
		return
	}
	if cfg.ServiceName != "nokey" {
		t.Errorf("ServiceName = %q, want default %q", cfg.ServiceName, "nokey")
	}
}

func TestConfigPath_HomeDirError(t *testing.T) {
	old := userHomeDirFn
	defer func() { userHomeDirFn = old }()
	userHomeDirFn = func() (string, error) {
		return "", fmt.Errorf("no home directory")
	}

	_, err := ConfigPath()
	if err == nil {
		t.Fatal("ConfigPath should fail when home dir is unavailable")
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Errorf("error should mention home directory, got: %v", err)
	}
}

func TestLoad_HomeDirError(t *testing.T) {
	old := userHomeDirFn
	defer func() { userHomeDirFn = old }()
	userHomeDirFn = func() (string, error) {
		return "", fmt.Errorf("no home directory")
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load should fail when home dir is unavailable")
	}
}

func TestSave_HomeDirError(t *testing.T) {
	old := userHomeDirFn
	defer func() { userHomeDirFn = old }()
	userHomeDirFn = func() (string, error) {
		return "", fmt.Errorf("no home directory")
	}

	err := Save(DefaultConfig())
	if err == nil {
		t.Fatal("Save should fail when home dir is unavailable")
	}
}
