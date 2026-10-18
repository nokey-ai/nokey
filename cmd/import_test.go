package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	kring "github.com/byteness/keyring"
	"github.com/nokey-ai/nokey/internal/config"
	nkeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// orderRing records the order in which keys are written.
type orderRing struct {
	*mockRing
	order []string
}

func (o *orderRing) Set(item kring.Item) error {
	o.order = append(o.order, item.Key)
	return o.mockRing.Set(item)
}

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunImport_StripsExportPrefix(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	envFile := writeEnvFile(t, "export API_KEY=abc\nexport  SPACED='x y'\nexported_name=keep\n")

	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := runImport(nil, []string{envFile}); err != nil {
				t.Fatalf("runImport: %v", err)
			}
		})
	})

	for key, want := range map[string]string{"API_KEY": "abc", "SPACED": "x y", "exported_name": "keep"} {
		got, err := store.Get(key)
		if err != nil {
			t.Fatalf("store.Get(%s): %v", key, err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestRunImport_WritesInSortedOrder(t *testing.T) {
	ring := &orderRing{mockRing: newMockRing()}
	store := nkeyring.NewWithRing(ring, "nokey-test")
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	envFile := writeEnvFile(t, "ZETA=1\nALPHA=2\nMIKE=3\nBRAVO=4\nYANKEE=5\n")

	_ = captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := runImport(nil, []string{envFile}); err != nil {
				t.Fatalf("runImport: %v", err)
			}
		})
	})

	want := []string{"ALPHA", "BRAVO", "MIKE", "YANKEE", "ZETA"}
	if strings.Join(ring.order, ",") != strings.Join(want, ",") {
		t.Errorf("write order = %v, want %v", ring.order, want)
	}
}

func TestRunImport_DryRun(t *testing.T) {
	store, ring := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = true
	withTestConfig(t, c)
	withTestAuditDir(t)

	old := importDryRun
	t.Cleanup(func() { importDryRun = old })
	importDryRun = true

	envFile := writeEnvFile(t, "B_KEY=2\nA_KEY=1\n")

	output := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := runImport(nil, []string{envFile}); err != nil {
				t.Fatalf("runImport: %v", err)
			}
		})
	})

	if len(ring.items) != 0 {
		t.Errorf("dry run wrote %d keyring items, want 0", len(ring.items))
	}
	if !strings.Contains(output, "Would import 2 secret(s)") {
		t.Errorf("output = %q, want dry-run summary", output)
	}
	if strings.Index(output, "A_KEY") > strings.Index(output, "B_KEY") || !strings.Contains(output, "A_KEY") {
		t.Errorf("output = %q, want sorted names", output)
	}
	if strings.Contains(output, "Successfully imported") {
		t.Errorf("dry run should not report an import: %q", output)
	}
}

func TestRunImport_DryRunFlagsInvalidNames(t *testing.T) {
	store, _ := newTestStore()
	withTestKeyring(t, store)
	withTestConfig(t, config.DefaultConfig())

	old := importDryRun
	t.Cleanup(func() { importDryRun = old })
	importDryRun = true

	envFile := writeEnvFile(t, "GOOD=1\nBAD$NAME=2\n")

	output := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			if err := runImport(nil, []string{envFile}); err != nil {
				t.Fatalf("runImport: %v", err)
			}
		})
	})

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "BAD$NAME") && !strings.Contains(line, "invalid") {
			t.Errorf("line %q should flag the invalid name", line)
		}
		if strings.Contains(line, "GOOD") && strings.Contains(line, "invalid") {
			t.Errorf("line %q should not be flagged", line)
		}
	}
}
