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
