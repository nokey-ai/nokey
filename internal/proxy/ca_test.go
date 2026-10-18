package proxy

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestLoadOrCreateCA_NewCA(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if ca.Cert == nil {
		t.Fatal("expected non-nil cert")
	}
	if ca.Key == nil {
		t.Fatal("expected non-nil key")
	}
	if len(ca.CertPEM) == 0 {
		t.Fatal("expected non-empty CertPEM")
	}
	if !ca.Cert.IsCA {
		t.Error("expected IsCA to be true")
	}
	if ca.Cert.Subject.CommonName != "nokey local proxy CA" {
		t.Errorf("unexpected CN: %s", ca.Cert.Subject.CommonName)
	}

	// Verify files were written.
	caDir := filepath.Join(dir, "ca")
	if _, err := os.Stat(filepath.Join(caDir, "ca-cert.pem")); err != nil {
		t.Errorf("cert file not found: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca-key.pem")); err != nil {
		t.Errorf("key file not found: %v", err)
	}

	// Verify directory permissions.
	info, err := os.Stat(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("ca dir perms = %o, want 0700", perm)
	}

	// Verify key file permissions.
	keyInfo, err := os.Stat(filepath.Join(caDir, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("key file perms = %o, want 0600", perm)
	}
}

func TestLoadOrCreateCA_Roundtrip(t *testing.T) {
	dir := t.TempDir()

	ca1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}

	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}

	// Should load the same cert.
	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Error("expected same serial number on reload")
	}
}

func TestGenerateHostCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	tests := []struct {
		host    string
		wantDNS bool
		wantIP  bool
	}{
		{"api.example.com", true, false},
		{"127.0.0.1", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			cert, err := ca.GenerateHostCert(tt.host)
			if err != nil {
				t.Fatalf("GenerateHostCert(%q): %v", tt.host, err)
			}

			// Parse the leaf cert.
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}

			if tt.wantDNS && len(leaf.DNSNames) == 0 {
				t.Error("expected DNS SANs")
			}
			if tt.wantIP && len(leaf.IPAddresses) == 0 {
				t.Error("expected IP SANs")
			}

			// Verify the cert is signed by the CA.
			pool := x509.NewCertPool()
			pool.AddCert(ca.Cert)
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if tt.wantDNS {
				opts.DNSName = tt.host
			}
			if _, err := leaf.Verify(opts); err != nil {
				t.Errorf("cert verification failed: %v", err)
			}
		})
	}
}

func TestGenerateHostCert_TLSUsable(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	cert, err := ca.GenerateHostCert("localhost")
	if err != nil {
		t.Fatalf("GenerateHostCert: %v", err)
	}

	// Ensure the cert can be used in a TLS config.
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Error("expected one certificate in TLS config")
	}
}

func TestParseCA_InvalidCertPEM(t *testing.T) {
	_, err := parseCA([]byte("not-a-pem"), []byte("also-not-pem"))
	if err == nil {
		t.Error("expected error for invalid cert PEM")
	}
}

func TestParseCA_InvalidKeyPEM(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	_, err = parseCA(ca.CertPEM, []byte("not-a-pem"))
	if err == nil {
		t.Error("expected error for invalid key PEM")
	}
}

func TestParseCA_ValidCertButInvalidKeyDER(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	// Valid PEM block wrapping garbage DER data
	fakeKeyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----\n")
	_, err = parseCA(ca.CertPEM, fakeKeyPEM)
	if err == nil {
		t.Error("expected error for invalid key DER inside valid PEM block")
	}
}

func TestLoadOrCreateCA_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	// Create a file where the "ca" directory should be, so MkdirAll fails.
	caPath := filepath.Join(dir, "ca")
	if err := os.WriteFile(caPath, []byte("block"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := LoadOrCreateCA(dir)
	if err == nil {
		t.Error("expected error when ca dir cannot be created")
	}
}

func TestLoadOrCreateCA_CertOnlyNoKey(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Only the cert exists. Regenerating would overwrite a cert the user may
	// have installed in a trust store, so this must be an error instead.
	certPath := filepath.Join(caDir, "ca-cert.pem")
	if err := os.WriteFile(certPath, []byte("whatever"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("expected error when only the CA cert exists")
	}
	got, _ := os.ReadFile(certPath)
	if string(got) != "whatever" {
		t.Errorf("CA cert was overwritten: %q", got)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca-key.pem")); !os.IsNotExist(err) {
		t.Errorf("expected no key to be written, Stat err = %v", err)
	}
}

func TestLoadOrCreateCA_UnreadableCertNotOverwritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0000 does not block reads on Windows")
	}
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	certPath := filepath.Join(dir, "ca", "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca", "ca-key.pem")
	origKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certPath, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(certPath, 0600) })

	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("expected error when the CA cert cannot be read")
	}
	gotKey, _ := os.ReadFile(keyPath)
	if string(gotKey) != string(origKey) {
		t.Error("CA key was regenerated after a cert read error")
	}
}

func TestLoadOrCreateCA_Concurrent(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	cas := make([]*CA, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cas[i], errs[i] = LoadOrCreateCA(dir)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("LoadOrCreateCA[%d]: %v", i, errs[i])
		}
		if !cas[i].Cert.Equal(cas[0].Cert) {
			t.Fatalf("LoadOrCreateCA[%d] returned a different CA", i)
		}
	}
	// What is on disk must be the same, self-consistent CA.
	disk, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !disk.Cert.Equal(cas[0].Cert) {
		t.Error("on-disk CA differs from the one returned to callers")
	}
}

func TestParseCA_KeyMismatch(t *testing.T) {
	a, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bDir := t.TempDir()
	if _, err := LoadOrCreateCA(bDir); err != nil {
		t.Fatal(err)
	}
	bKey, err := os.ReadFile(filepath.Join(bDir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCA(a.CertPEM, bKey); err == nil {
		t.Error("expected error when the key does not match the cert")
	}
}

func TestParseCA_NotCA(t *testing.T) {
	ca := newTestCA(t)
	leaf, err := ca.GenerateHostCert("example.com")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if _, err := parseCA(certPEM, keyPEM); err == nil {
		t.Error("expected error for a non-CA certificate")
	}
}

// withoutHardLinks makes linkFn fail the way it does on filesystems
// without hard link support (FAT/exFAT, some SMB and FUSE mounts).
func withoutHardLinks(t *testing.T) {
	t.Helper()
	old := linkFn
	t.Cleanup(func() { linkFn = old })
	linkFn = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errors.ErrUnsupported}
	}
}

func TestLoadOrCreateCA_NoHardLinks(t *testing.T) {
	withoutHardLinks(t)
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA without hard links: %v", err)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "ca", "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key perms = %o, want 0600", keyInfo.Mode().Perm())
	}
	again, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !again.Cert.Equal(ca.Cert) {
		t.Error("reload returned a different CA")
	}
}

func TestLoadOrCreateCA_ConcurrentNoHardLinks(t *testing.T) {
	withoutHardLinks(t)
	dir := t.TempDir()
	const n = 8
	cas := make([]*CA, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cas[i], errs[i] = LoadOrCreateCA(dir)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("LoadOrCreateCA[%d]: %v", i, errs[i])
		}
		if !cas[i].Cert.Equal(cas[0].Cert) {
			t.Fatalf("LoadOrCreateCA[%d] returned a different CA", i)
		}
	}
}

func TestLoadOrCreateCA_StaleKeyOnlyRegenerates(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	// A crash between writing the key and the cert leaves only the key.
	// No cert was ever written, so nothing can trust it: safe to replace.
	keyPath := filepath.Join(caDir, "ca-key.pem")
	if err := os.WriteFile(keyPath, []byte("orphaned key"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(keyPath, old, old); err != nil {
		t.Fatal(err)
	}

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA with stale key-only dir: %v", err)
	}
	if ca.Cert == nil {
		t.Fatal("expected a regenerated CA")
	}
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Errorf("reload after regeneration: %v", err)
	}
}

func TestLoadOrCreateCA_StaleCorruptCAFailsFast(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Corrupt files this old cannot be a concurrent creator mid-write, so
	// there is nothing to wait for.
	old := time.Now().Add(-time.Minute)
	for _, name := range []string{"ca-cert.pem", "ca-key.pem"} {
		p := filepath.Join(caDir, name)
		if err := os.WriteFile(p, []byte("corrupt"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}

	start := time.Now()
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("expected error for a corrupt CA")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("LoadOrCreateCA took %v on a stale corrupt CA, want it to fail fast", elapsed)
	}
}
