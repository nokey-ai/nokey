package keyring

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestMigrateFileBackendDir_NoOpWhenNewDirExists(t *testing.T) {
	tmp := t.TempDir()
	old := tmp
	newDir := filepath.Join(tmp, "keyring")
	writeFile(t, filepath.Join(old, "SECRET_A"), "cipher-a")
	if err := os.Mkdir(newDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := migrateFileBackendDir(old, newDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(old, "SECRET_A")); err != nil {
		t.Errorf("SECRET_A should remain in old dir when new dir already exists: %v", err)
	}
	if names := dirNames(t, newDir); len(names) != 0 {
		t.Errorf("new dir should stay empty when already present, got %v", names)
	}
}

func TestMigrateFileBackendDir_NoOpWhenOldDirMissing(t *testing.T) {
	tmp := t.TempDir()
	if err := migrateFileBackendDir(filepath.Join(tmp, "nope"), filepath.Join(tmp, "keyring")); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func TestMigrateFileBackendDir_MovesCandidatesPreservesReserved(t *testing.T) {
	tmp := t.TempDir()
	old := tmp
	newDir := filepath.Join(tmp, "keyring")

	writeFile(t, filepath.Join(old, "SECRET_A"), "ciphertext-A-payload")
	writeFile(t, filepath.Join(old, "SECRET_B"), "ciphertext-B")
	writeFile(t, filepath.Join(old, "config.yaml"), "redact_by_default: false\n")
	writeFile(t, filepath.Join(old, "policies.yaml"), "approval: never\n")
	writeFile(t, filepath.Join(old, "audit.log"), "<log>\n")
	writeFile(t, filepath.Join(old, "chain_head.json"), "{}\n")
	writeFile(t, filepath.Join(old, "session_ticket"), "ticket-bytes")
	writeFile(t, filepath.Join(old, ".dotfile"), "ignored")
	if err := os.Mkdir(filepath.Join(old, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := migrateFileBackendDir(old, newDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	gotNew := dirNames(t, newDir)
	wantNew := []string{"SECRET_A", "SECRET_B"}
	if strings.Join(gotNew, ",") != strings.Join(wantNew, ",") {
		t.Errorf("new dir = %v, want %v", gotNew, wantNew)
	}

	for _, name := range []string{"SECRET_A", "SECRET_B"} {
		if _, err := os.Stat(filepath.Join(old, name)); !os.IsNotExist(err) {
			t.Errorf("%s should be removed from old dir, stat err = %v", name, err)
		}
	}

	for _, name := range []string{"config.yaml", "policies.yaml", "audit.log", "chain_head.json", "session_ticket", ".dotfile", "subdir"} {
		if _, err := os.Stat(filepath.Join(old, name)); err != nil {
			t.Errorf("%s should remain in old dir: %v", name, err)
		}
	}

	got, err := os.ReadFile(filepath.Join(newDir, "SECRET_A"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ciphertext-A-payload" {
		t.Errorf("payload after migrate = %q, want preserved bytes", got)
	}
}

func TestMigrateFileBackendDir_NoCandidatesSkipsCreate(t *testing.T) {
	tmp := t.TempDir()
	old := tmp
	newDir := filepath.Join(tmp, "keyring")
	writeFile(t, filepath.Join(old, "config.yaml"), "x")
	writeFile(t, filepath.Join(old, "audit.log"), "y")

	if err := migrateFileBackendDir(old, newDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := os.Stat(newDir); !os.IsNotExist(err) {
		t.Errorf("new dir should not be created when no candidates exist, stat err = %v", err)
	}
}

func TestSafeMoveFile_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	dst := filepath.Join(tmp, "dst")
	writeFile(t, src, "payload-bytes-1234567890")

	if err := safeMoveFile(src, dst); err != nil {
		t.Fatalf("safeMoveFile: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src should be removed, stat err = %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload-bytes-1234567890" {
		t.Errorf("dst contents = %q", got)
	}
}
