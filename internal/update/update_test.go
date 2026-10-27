package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	zw.Close()
	return buf.Bytes()
}

// fakeRelease serves a GitHub API "latest release" plus its assets.
func fakeRelease(t *testing.T, tag string, archives map[string][]byte, tamper bool) *Client {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var sums strings.Builder
	rel := Release{TagName: tag}
	for name, data := range archives {
		sum := sha256.Sum256(data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
		rel.Assets = append(rel.Assets, Asset{Name: name, URL: srv.URL + "/dl/" + name})
		served := data
		if tamper {
			served = append([]byte("x"), data...)
		}
		mux.HandleFunc("/dl/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(served) })
	}
	rel.Assets = append(rel.Assets, Asset{Name: "checksums.txt", URL: srv.URL + "/dl/checksums.txt"})
	mux.HandleFunc("/dl/checksums.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sums.String())) })
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(rel)
	})
	return &Client{HTTP: srv.Client(), BaseURL: srv.URL}
}

func TestLatestAndDownload_TarGz(t *testing.T) {
	bin := []byte("new nokey binary")
	name := ArchiveName("1.2.3", "darwin", "arm64")
	c := fakeRelease(t, "v1.2.3", map[string][]byte{
		name: tarGz(t, map[string][]byte{"README.md": []byte("readme"), "nokey": bin}),
	}, false)

	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if rel.Version() != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", rel.Version())
	}
	got, err := c.Download(context.Background(), rel, "darwin", "arm64")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(got, bin) {
		t.Errorf("binary = %q, want %q", got, bin)
	}
}

func TestDownload_Zip(t *testing.T) {
	bin := []byte("windows binary")
	name := ArchiveName("1.2.3", "windows", "amd64")
	c := fakeRelease(t, "v1.2.3", map[string][]byte{
		name: zipArchive(t, map[string][]byte{"nokey.exe": bin}),
	}, false)
	rel, _ := c.Latest(context.Background())
	got, err := c.Download(context.Background(), rel, "windows", "amd64")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if !bytes.Equal(got, bin) {
		t.Errorf("binary = %q, want %q", got, bin)
	}
}

func TestDownload_ChecksumMismatch(t *testing.T) {
	name := ArchiveName("1.2.3", "linux", "amd64")
	c := fakeRelease(t, "v1.2.3", map[string][]byte{
		name: tarGz(t, map[string][]byte{"nokey": []byte("bin")}),
	}, true)
	rel, _ := c.Latest(context.Background())
	_, err := c.Download(context.Background(), rel, "linux", "amd64")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want checksum mismatch", err)
	}
}

func TestDownload_NoBuildForPlatform(t *testing.T) {
	c := fakeRelease(t, "v1.2.3", map[string][]byte{
		ArchiveName("1.2.3", "linux", "amd64"): tarGz(t, map[string][]byte{"nokey": []byte("bin")}),
	}, false)
	rel, _ := c.Latest(context.Background())
	_, err := c.Download(context.Background(), rel, "plan9", "386")
	if err == nil || !strings.Contains(err.Error(), "no build for plan9/386") {
		t.Fatalf("err = %v, want no build", err)
	}
}

func TestDownload_ArchiveWithoutBinary(t *testing.T) {
	name := ArchiveName("1.2.3", "linux", "amd64")
	c := fakeRelease(t, "v1.2.3", map[string][]byte{
		name: tarGz(t, map[string][]byte{"README.md": []byte("readme")}),
	}, false)
	rel, _ := c.Latest(context.Background())
	_, err := c.Download(context.Background(), rel, "linux", "amd64")
	if err == nil || !strings.Contains(err.Error(), "archive has no nokey") {
		t.Fatalf("err = %v, want missing binary", err)
	}
}

func TestLatest_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := &Client{HTTP: srv.Client(), BaseURL: srv.URL}
	if _, err := c.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want 403", err)
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nokey")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Replace(path, []byte("new"), runtime.GOOS); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("contents = %q, want new", got)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o755 {
			t.Errorf("mode = %v, want 0755", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want only the binary", len(entries))
	}
}

func TestReplace_WindowsMovesOldAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nokey.exe")
	os.WriteFile(path, []byte("old"), 0o755)
	if err := Replace(path, []byte("new"), "windows"); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".old")
	if string(got) != "new" || string(old) != "old" {
		t.Errorf("new = %q, old = %q", got, old)
	}
}

func TestNewer(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.6.6", "0.6.5", true},
		{"v0.7.0", "0.6.9", true},
		{"1.0.0", "0.99.99", true},
		{"0.6.5", "0.6.5", false},
		{"0.6.4", "v0.6.5", false},
		{"0.10.0", "0.9.0", true},
	}
	for _, tt := range tests {
		got, err := Newer(tt.a, tt.b)
		if err != nil {
			t.Fatalf("Newer(%q, %q): %v", tt.a, tt.b, err)
		}
		if got != tt.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestIsRelease(t *testing.T) {
	for v, want := range map[string]bool{
		"0.6.5":             true,
		"v0.6.5":            true,
		"dev":               false,
		"v0.6.5-3-gabc1234": false,
		"v0.6.5-dirty":      false,
		"c6cb909":           false,
		"1.2":               false,
	} {
		if got := IsRelease(v); got != want {
			t.Errorf("IsRelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestHomebrewManaged(t *testing.T) {
	for path, want := range map[string]bool{
		"/opt/homebrew/Caskroom/nokey/0.6.5/nokey":  true,
		"/usr/local/Cellar/nokey/0.6.5/bin/nokey":   true,
		"/home/linuxbrew/.linuxbrew/Cellar/nokey/x": true,
		"/usr/local/bin/nokey":                      false,
		"/Users/me/go/bin/nokey":                    false,
	} {
		if got := HomebrewManaged(path); got != want {
			t.Errorf("HomebrewManaged(%q) = %v, want %v", path, got, want)
		}
	}
}
