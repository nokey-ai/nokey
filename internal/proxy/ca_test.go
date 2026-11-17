package proxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestLoadOrCreateCA_NewCA(t *testing.T) {
	dir := t.TempDir()
	keys := newMemKeys()

	var ca *CA
	stderr := captureStderr(t, func() {
		var err error
		if ca, err = LoadOrCreateCA(dir, keys, testCAHosts); err != nil {
			t.Fatalf("LoadOrCreateCA: %v", err)
		}
	})
	if stderr != "" {
		t.Errorf("a first CA replaces nothing, but stderr = %q", stderr)
	}
	if ca.Cert == nil || ca.Key == nil || len(ca.CertPEM) == 0 {
		t.Fatalf("incomplete CA: %+v", ca)
	}
	if !ca.Cert.IsCA {
		t.Error("expected IsCA to be true")
	}
	if ca.Cert.Subject.CommonName != caCommonName {
		t.Errorf("unexpected CN: %s", ca.Cert.Subject.CommonName)
	}
	if life := time.Until(ca.Cert.NotAfter); life > caLifetime {
		t.Errorf("CA is valid for %v, want at most %v", life, caLifetime)
	}

	caDir := filepath.Join(dir, "ca")
	if _, err := os.Stat(filepath.Join(caDir, "ca-cert.pem")); err != nil {
		t.Errorf("cert file not found: %v", err)
	}
	// The key belongs in the keyring and nowhere on disk.
	if keys.key == "" {
		t.Error("CA key was not stored in the key store")
	}
	entries, err := os.ReadDir(caDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(caDir, e.Name()))
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Errorf("%s holds a private key", e.Name())
		}
	}

	info, err := os.Stat(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0700 {
		t.Errorf("ca dir perms = %o, want 0700", perm)
	}
}

func TestLoadOrCreateCA_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	keys := newMemKeys()

	ca1, err := LoadOrCreateCA(dir, keys, testCAHosts)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}
	// Fewer hosts are still covered, so the CA stays.
	ca2, err := LoadOrCreateCA(dir, keys, []string{"api.example.com"})
	if err != nil {
		t.Fatalf("second LoadOrCreateCA: %v", err)
	}
	if !ca1.Cert.Equal(ca2.Cert) {
		t.Error("expected the same CA on reload")
	}
}

// A stolen CA key must be worth nothing outside the proxy rule hosts.
func TestCA_SignsOnlyForRuleHosts(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		leaf  string
		ok    bool
	}{
		{"listed name", []string{"api.example.com"}, "api.example.com", true},
		{"other name", []string{"api.example.com"}, "evil.test", false},
		{"sibling name", []string{"api.example.com"}, "www.example.com", false},
		{"wildcard subdomain", []string{"*.example.com"}, "a.b.example.com", true},
		{"wildcard, other domain", []string{"*.example.com"}, "example.org", false},
		{"partial wildcard", []string{"api-*.example.com"}, "api-1.example.com", true},
		{"listed IP", []string{"127.0.0.1"}, "127.0.0.1", true},
		{"other IP", []string{"127.0.0.1"}, "10.0.0.1", false},
		{"IP when only names are listed", []string{"api.example.com"}, "10.0.0.1", false},
		{"IPv6 when only names are listed", []string{"api.example.com"}, "::1", false},
		{"name when only IPs are listed", []string{"127.0.0.1"}, "evil.test", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, err := LoadOrCreateCA(t.TempDir(), newMemKeys(), tt.hosts)
			if err != nil {
				t.Fatalf("LoadOrCreateCA: %v", err)
			}
			cert, err := ca.GenerateHostCert(tt.leaf)
			if err != nil {
				t.Fatalf("GenerateHostCert: %v", err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca.Cert)
			opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if net.ParseIP(tt.leaf) == nil {
				opts.DNSName = tt.leaf
			}
			_, err = leaf.Verify(opts)
			if (err == nil) != tt.ok {
				t.Errorf("verify %q under a CA for %v: err = %v, want ok = %v", tt.leaf, tt.hosts, err, tt.ok)
			}
		})
	}
}

// The CA is for TLS servers only.
func TestCA_NotForClientAuth(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.GenerateHostCert("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("leaf verified for client auth")
	}
}

func TestNameConstraints_RefusesUnboundedPatterns(t *testing.T) {
	for _, hosts := range [][]string{nil, {"*"}, {"api.*"}, {"10.0.0.*"}, {"*.com."}, {"api.example.com", "*"}} {
		if _, err := LoadOrCreateCA(t.TempDir(), newMemKeys(), hosts); err == nil {
			t.Errorf("hosts %q: expected an error, the CA can't be limited to them", hosts)
		}
	}
}

// writeLegacyCA puts an old-style CA in dir: unconstrained, key on disk.
func writeLegacyCA(t *testing.T, dir string) (certPEM []byte) {
	t.Helper()
	gen, err := generateCA(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca-cert.pem"), gen.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca-key.pem"), gen.keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return gen.CertPEM
}

// A CA from before the key moved to the keyring is replaced, its key file
// removed, and the user told to distrust it.
func TestLoadOrCreateCA_ReplacesLegacyCA(t *testing.T) {
	dir := t.TempDir()
	oldCert := writeLegacyCA(t, dir)
	keys := newMemKeys()

	var ca *CA
	stderr := captureStderr(t, func() {
		var err error
		if ca, err = LoadOrCreateCA(dir, keys, testCAHosts); err != nil {
			t.Fatalf("LoadOrCreateCA: %v", err)
		}
	})
	if bytes.Equal(ca.CertPEM, oldCert) {
		t.Error("the legacy CA is still in use")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca", "ca-key.pem")); !os.IsNotExist(err) {
		t.Errorf("legacy key file still exists: %v", err)
	}
	for _, want := range []string{"made a new proxy CA", "unencrypted file", "system trust store"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, "ca", "ca-cert.pem"))
	if !bytes.Equal(onDisk, ca.CertPEM) {
		t.Error("cert on disk is not the new CA's")
	}
}

func TestLoadOrCreateCA_ReplacesUnfitCA(t *testing.T) {
	tests := []struct {
		name   string
		damage func(t *testing.T, dir string, keys *memKeys)
		hosts  []string
		want   string
	}{
		{"new rule host", func(*testing.T, string, *memKeys) {}, []string{"api.other.test"}, `does not cover the proxy rule host "api.other.test"`},
		{"new rule IP", func(*testing.T, string, *memKeys) {}, []string{"10.1.2.3"}, `does not cover the proxy rule host "10.1.2.3"`},
		{"key gone from keyring", func(_ *testing.T, _ string, keys *memKeys) { keys.key = "" }, testCAHosts, "key is not in the keyring"},
		{"cert gone", func(t *testing.T, dir string, _ *memKeys) {
			if err := os.Remove(filepath.Join(dir, "ca", "ca-cert.pem")); err != nil {
				t.Fatal(err)
			}
		}, testCAHosts, "certificate is missing"},
		{"key of another CA", func(t *testing.T, _ string, keys *memKeys) {
			other, err := generateCA([]string{"example.com"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			keys.key = string(other.keyPEM)
		}, testCAHosts, "unusable"},
		{"near expiry", func(t *testing.T, dir string, keys *memKeys) {
			// Re-sign the stored CA to end inside the renewal window.
			ca, _, err := loadCA(filepath.Join(dir, "ca", "ca-cert.pem"), filepath.Join(dir, "ca", "ca-key.pem"), keys, nil, nil)
			if err != nil || ca == nil {
				t.Fatalf("loadCA: %v, %v", ca, err)
			}
			tmpl := *ca.Cert
			tmpl.NotAfter = time.Now().Add(caRenewBefore - time.Hour)
			der, err := x509.CreateCertificate(nil, &tmpl, &tmpl, ca.Cert.PublicKey, ca.Key)
			if err != nil {
				t.Fatal(err)
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			if err := os.WriteFile(filepath.Join(dir, "ca", "ca-cert.pem"), certPEM, 0600); err != nil {
				t.Fatal(err)
			}
		}, testCAHosts, "expires on"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			keys := newMemKeys()
			first, err := LoadOrCreateCA(dir, keys, testCAHosts)
			if err != nil {
				t.Fatal(err)
			}
			tt.damage(t, dir, keys)

			var second *CA
			stderr := captureStderr(t, func() {
				if second, err = LoadOrCreateCA(dir, keys, tt.hosts); err != nil {
					t.Fatalf("LoadOrCreateCA: %v", err)
				}
			})
			if second.Cert.Equal(first.Cert) {
				t.Error("the unfit CA is still in use")
			}
			if !strings.Contains(stderr, tt.want) || !strings.Contains(stderr, "must trust the new one") {
				t.Errorf("stderr = %q, want the reason %q and the re-trust notice", stderr, tt.want)
			}
			// The replacement is stable.
			third, err := LoadOrCreateCA(dir, keys, tt.hosts)
			if err != nil || !third.Cert.Equal(second.Cert) {
				t.Errorf("reload after replacement: %v", err)
			}
		})
	}
}

// A keyring that can't be read (locked, say) may hold a good key, so the
// CA is not replaced behind it.
func TestLoadOrCreateCA_KeyringErrorKeepsCA(t *testing.T) {
	dir := t.TempDir()
	keys := newMemKeys()
	if _, err := LoadOrCreateCA(dir, keys, testCAHosts); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "ca", "ca-cert.pem")
	before, _ := os.ReadFile(certPath)

	keys.getErr = errors.New("keychain is locked")
	if _, err := LoadOrCreateCA(dir, keys, testCAHosts); err == nil || !strings.Contains(err.Error(), "keychain is locked") {
		t.Fatalf("error = %v, want the keyring failure", err)
	}
	after, _ := os.ReadFile(certPath)
	if !bytes.Equal(before, after) {
		t.Error("CA cert was replaced after a keyring read error")
	}
}

func TestLoadOrCreateCA_UnreadableCertNotOverwritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0000 does not block reads on Windows")
	}
	dir := t.TempDir()
	keys := newMemKeys()
	if _, err := LoadOrCreateCA(dir, keys, testCAHosts); err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	certPath := filepath.Join(dir, "ca", "ca-cert.pem")
	origKey := keys.key
	if err := os.Chmod(certPath, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(certPath, 0600) })

	if _, err := LoadOrCreateCA(dir, keys, testCAHosts); err == nil {
		t.Fatal("expected error when the CA cert cannot be read")
	}
	if keys.key != origKey {
		t.Error("CA key was regenerated after a cert read error")
	}
}

func TestLoadOrCreateCA_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	// Create a file where the "ca" directory should be, so MkdirAll fails.
	if err := os.WriteFile(filepath.Join(dir, "ca"), []byte("block"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := LoadOrCreateCA(dir, newMemKeys(), testCAHosts); err == nil {
		t.Error("expected error when ca dir cannot be created")
	}
}

func TestLoadOrCreateCA_Concurrent(t *testing.T) {
	dir := t.TempDir()
	keys := newMemKeys()
	const n = 8
	cas := make([]*CA, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cas[i], errs[i] = LoadOrCreateCA(dir, keys, testCAHosts)
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
	// What is stored must be the same, self-consistent CA.
	stored, err := LoadOrCreateCA(dir, keys, testCAHosts)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !stored.Cert.Equal(cas[0].Cert) {
		t.Error("stored CA differs from the one returned to callers")
	}
}

func TestGenerateHostCert(t *testing.T) {
	ca := newTestCA(t)

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
	ca := newTestCA(t)

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
	ca := newTestCA(t)
	if _, err := parseCA(ca.CertPEM, []byte("not-a-pem")); err == nil {
		t.Error("expected error for invalid key PEM")
	}
}

func TestParseCA_ValidCertButInvalidKeyDER(t *testing.T) {
	ca := newTestCA(t)
	// Valid PEM block wrapping garbage DER data
	fakeKeyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----\n")
	if _, err := parseCA(ca.CertPEM, fakeKeyPEM); err == nil {
		t.Error("expected error for invalid key DER inside valid PEM block")
	}
}

func TestParseCA_KeyMismatch(t *testing.T) {
	a := newTestCA(t)
	bKeys := newMemKeys()
	if _, err := LoadOrCreateCA(t.TempDir(), bKeys, testCAHosts); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCA(a.CertPEM, []byte(bKeys.key)); err == nil {
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
