package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
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
