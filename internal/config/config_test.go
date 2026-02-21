package config

import (
	"os"
	"path/filepath"
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
	if !contains(path, filepath.Join(".config", "nokey")) {
		t.Errorf("Expected path to contain .config/nokey, got %q", path)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
