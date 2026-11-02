package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
)

func TestInit_CreatesFiles(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tmpDir := t.TempDir()
	old := config.ConfigDir
	t.Cleanup(func() { config.ConfigDir = old })
	config.ConfigDir = func() (string, error) { return tmpDir, nil }

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init: %v", err)
		}
	})

	// Config file should exist
	if _, err := os.Stat(filepath.Join(tmpDir, "config.yaml")); err != nil {
		t.Error("config.yaml not created")
	}
	// Policies file should exist
	if _, err := os.Stat(filepath.Join(tmpDir, "policies.yaml")); err != nil {
		t.Error("policies.yaml not created")
	}
	if !strings.Contains(out, "Created") {
		t.Errorf("output should contain 'Created', got: %s", out)
	}
}

func TestInit_SkipsExisting(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tmpDir := t.TempDir()
	old := config.ConfigDir
	t.Cleanup(func() { config.ConfigDir = old })
	config.ConfigDir = func() (string, error) { return tmpDir, nil }

	// Pre-create the files
	os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte("existing"), 0600)
	os.WriteFile(filepath.Join(tmpDir, "policies.yaml"), []byte("existing"), 0600)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init: %v", err)
		}
	})

	if !strings.Contains(out, "Skipped") {
		t.Errorf("output should contain 'Skipped', got: %s", out)
	}

	// Files should not be overwritten
	data, _ := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if string(data) != "existing" {
		t.Error("config.yaml was overwritten without --force")
	}
}

func TestInit_Force(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	tmpDir := t.TempDir()
	old := config.ConfigDir
	t.Cleanup(func() { config.ConfigDir = old })
	config.ConfigDir = func() (string, error) { return tmpDir, nil }

	// Pre-create the files
	os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte("existing"), 0600)
	os.WriteFile(filepath.Join(tmpDir, "policies.yaml"), []byte("existing"), 0600)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"init", "--force"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init --force: %v", err)
		}
	})

	if !strings.Contains(out, "Created") {
		t.Errorf("output should contain 'Created', got: %s", out)
	}

	// Files should be overwritten
	data, _ := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if string(data) == "existing" {
		t.Error("config.yaml was not overwritten with --force")
	}
}

func TestInit_WriteError(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := config.ConfigDir
	t.Cleanup(func() { config.ConfigDir = old })
	config.ConfigDir = func() (string, error) { return "/nonexistent/path/nokey", nil }

	// Override writeInitFile to simulate failure
	oldWrite := writeInitFile
	t.Cleanup(func() { writeInitFile = oldWrite })
	writeInitFile = func(path string, content []byte, force bool) (bool, error) {
		return false, os.ErrPermission
	}

	rootCmd.SetArgs([]string{"init"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("init should fail when write fails")
	}
}
