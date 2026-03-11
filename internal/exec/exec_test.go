package exec

import (
	"testing"
)

func TestRun_EmptyCommand(t *testing.T) {
	exitCode, err := Run("", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
}

func TestRun_SuccessfulCommand(t *testing.T) {
	exitCode, err := Run("echo", []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRun_NonZeroExit(t *testing.T) {
	exitCode, err := Run("sh", []string{"-c", "exit 42"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exit code = %d, want 42", exitCode)
	}
}

func TestRun_FalseCommand(t *testing.T) {
	exitCode, err := Run("false", nil, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
}

func TestRun_SecretsInEnv(t *testing.T) {
	secrets := map[string]string{"TEST_SECRET_NOKEY": "supersecret123"}
	exitCode, err := Run("sh", []string{"-c", `test "$TEST_SECRET_NOKEY" = supersecret123`}, secrets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (secret should be in env)", exitCode)
	}
}

func TestRun_MultipleSecrets(t *testing.T) {
	secrets := map[string]string{
		"SECRET_A": "alpha",
		"SECRET_B": "bravo",
	}
	exitCode, err := Run("sh", []string{"-c", `test "$SECRET_A" = alpha && test "$SECRET_B" = bravo`}, secrets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRun_ExtraEnv(t *testing.T) {
	exitCode, err := Run("sh", []string{"-c", `test "$EXTRA_VAR_NOKEY" = extraval`}, nil, "EXTRA_VAR_NOKEY=extraval")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (extra env should be set)", exitCode)
	}
}

func TestRun_SecretsAndExtraEnv(t *testing.T) {
	secrets := map[string]string{"SEC": "secval"}
	exitCode, err := Run("sh", []string{"-c", `test "$SEC" = secval && test "$EXT" = extval`}, secrets, "EXT=extval")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRun_NonExistentCommand(t *testing.T) {
	exitCode, err := Run("nonexistent_command_xyz_nokey_test", nil, nil)
	if err == nil {
		t.Fatal("expected error for non-existent command")
	}
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
}

func TestRun_NilSecrets(t *testing.T) {
	exitCode, err := Run("true", nil, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRun_EmptySecrets(t *testing.T) {
	exitCode, err := Run("true", nil, map[string]string{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRun_CommandWithArgs(t *testing.T) {
	exitCode, err := Run("echo", []string{"-n", "test"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

func TestRun_SecretsOverrideExistingEnv(t *testing.T) {
	secrets := map[string]string{"PATH": "/custom/path"}
	exitCode, err := Run("sh", []string{"-c", `test "$PATH" = /custom/path`}, secrets)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (secret should override env)", exitCode)
	}
}
