package cmd

import (
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
)

func TestRunStatus_NoSecrets(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !strings.Contains(output, "nokey status:") {
		t.Error("output should contain header")
	}
	if !strings.Contains(output, "not configured") {
		t.Error("output should show PIN not configured")
	}
	if !strings.Contains(output, "Secrets stored:") {
		t.Error("output should show secrets count")
	}
}

func TestRunStatus_JSON(t *testing.T) {
	store, _ := newTestStore()
	store.Set("KEY1", "val")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := statusJSON
	t.Cleanup(func() { statusJSON = old })
	statusJSON = true

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})
	if !strings.Contains(output, `"keyring"`) {
		t.Errorf("JSON output should contain keyring: %q", output)
	}
	if !strings.Contains(output, `"secrets": 1`) {
		t.Errorf("JSON output should contain secrets count: %q", output)
	}
}

func TestRunStatus_WithPIN(t *testing.T) {
	store, _ := newTestStore()
	_ = store.SetPINHash("somehash")
	_ = store.Set("MY_KEY", "val")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	output := captureStdout(t, func() {
		if err := runStatus(nil, nil); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !strings.Contains(output, "configured") {
		t.Error("output should show PIN configured")
	}
	if !strings.Contains(output, "1") {
		t.Error("output should show 1 secret")
	}
}
