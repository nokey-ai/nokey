package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/update"
)

// withUpdateStubs points nokey update at a fake "latest release" endpoint
// serving tag, a fake current version, and an executable path.
func withUpdateStubs(t *testing.T, tag, current, exe string) *bool {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(update.Release{TagName: tag})
	}))
	t.Cleanup(srv.Close)

	brewRan := false
	oldClient, oldExe, oldCur, oldBrew := updateClientFn, updateExecutableFn, updateCurrentFn, updateBrewFn
	oldCheck, oldForce := updateCheck, updateForce
	t.Cleanup(func() {
		updateClientFn, updateExecutableFn, updateCurrentFn, updateBrewFn = oldClient, oldExe, oldCur, oldBrew
		updateCheck, updateForce = oldCheck, oldForce
	})
	updateClientFn = func() *update.Client { return &update.Client{HTTP: srv.Client(), BaseURL: srv.URL} }
	updateExecutableFn = func() (string, error) { return exe, nil }
	updateCurrentFn = func() string { return current }
	updateBrewFn = func(context.Context) error { brewRan = true; return nil }
	updateCheck, updateForce = false, false
	return &brewRan
}

func TestRunUpdate_AlreadyLatest(t *testing.T) {
	brewRan := withUpdateStubs(t, "v0.6.5", "0.6.5", "/opt/homebrew/Caskroom/nokey/0.6.5/nokey")
	out := captureStdout(t, func() {
		if err := runUpdate(nil, nil); err != nil {
			t.Fatalf("runUpdate: %v", err)
		}
	})
	if !strings.Contains(out, "0.6.5 is the latest release") {
		t.Errorf("output = %q", out)
	}
	if *brewRan {
		t.Error("brew should not run when already up to date")
	}
}

func TestRunUpdate_CheckOnly(t *testing.T) {
	brewRan := withUpdateStubs(t, "v0.7.0", "0.6.5", "/opt/homebrew/Caskroom/nokey/0.6.5/nokey")
	updateCheck = true
	out := captureStdout(t, func() {
		if err := runUpdate(nil, nil); err != nil {
			t.Fatalf("runUpdate: %v", err)
		}
	})
	if !strings.Contains(out, "0.7.0 is available") {
		t.Errorf("output = %q", out)
	}
	if *brewRan {
		t.Error("--check must not upgrade")
	}
}

func TestRunUpdate_HomebrewDelegates(t *testing.T) {
	brewRan := withUpdateStubs(t, "v0.7.0", "0.6.5", "/opt/homebrew/Caskroom/nokey/0.6.5/nokey")
	captureStdout(t, func() {
		if err := runUpdate(nil, nil); err != nil {
			t.Fatalf("runUpdate: %v", err)
		}
	})
	if !*brewRan {
		t.Error("expected brew upgrade for a Caskroom install")
	}
}

func TestRunUpdate_DevBuildNeedsForce(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "nokey")
	os.WriteFile(exe, []byte("dev"), 0o755)
	withUpdateStubs(t, "v0.7.0", "v0.6.5-3-gabc1234", exe)
	out := captureStdout(t, func() {
		if err := runUpdate(nil, nil); err != nil {
			t.Fatalf("runUpdate: %v", err)
		}
	})
	if !strings.Contains(out, "development build") || !strings.Contains(out, "--force") {
		t.Errorf("output = %q", out)
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "dev" {
		t.Error("dev build was replaced without --force")
	}
}
