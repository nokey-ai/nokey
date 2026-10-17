package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// CA holds the local proxy CA certificate and key used for MITM HTTPS interception.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.PrivateKey
	CertPEM []byte
}

var (
	// errCANotFound reports that neither CA file exists yet.
	errCANotFound = errors.New("CA not found")
	// errCAIncomplete reports that exactly one CA file exists, which is
	// also what a concurrent creator looks like between its two writes.
	errCAIncomplete = errors.New("CA files incomplete")
	// errCAKeyOnly is the errCAIncomplete case where only the key exists.
	errCAKeyOnly = fmt.Errorf("%w: key without cert", errCAIncomplete)
	// errCAInvalid reports CA files that do not parse, which is also what
	// a concurrent creator without hard links looks like mid-write.
	errCAInvalid = errors.New("invalid CA")
)

// staleKeyAge is how old an orphaned CA key must be before it is treated
// as left over from a crash rather than a creator still writing the cert.
const staleKeyAge = 5 * time.Second

// LoadOrCreateCA loads the CA from configDir/ca/ or creates a new one if
// neither file exists. Any other failure to load is returned rather than
// papered over with a new CA, which would invalidate a cert the user may
// already trust.
func LoadOrCreateCA(configDir string) (*CA, error) {
	caDir := filepath.Join(configDir, "ca")
	certPath := filepath.Join(caDir, "ca-cert.pem")
	keyPath := filepath.Join(caDir, "ca-key.pem")

	// Try to load existing CA.
	ca, err := loadCA(certPath, keyPath)
	if errors.Is(err, errCAKeyOnly) && removeStaleKey(keyPath) {
		// A crash between the key and cert writes. No cert was ever
		// written, so nothing can trust this key: regenerate.
		err = errCANotFound
	} else if errors.Is(err, errCAIncomplete) || errors.Is(err, errCAInvalid) {
		// Files this old cannot be a concurrent creator mid-write, so
		// report them now rather than waiting.
		if caFilesStale(certPath, keyPath) {
			return nil, err
		}
		return waitForCA(certPath, keyPath)
	}
	if !errors.Is(err, errCANotFound) {
		return ca, err
	}

	// Create new CA.
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	gen, err := generateCA()
	if err != nil {
		return nil, err
	}

	// The key is written first and exclusively, so of several concurrent
	// creators exactly one installs its CA.
	created, err := writeFileExclusive(keyPath, gen.keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to write CA key: %w", err)
	}
	if !created {
		return waitForCA(certPath, keyPath)
	}
	created, err = writeFileExclusive(certPath, gen.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to write CA cert: %w", err)
	}
	if !created {
		return nil, fmt.Errorf("CA cert %s appeared while creating a new CA; remove %s to regenerate", certPath, caDir)
	}

	return gen.CA, nil
}

// loadCA reads and parses the CA files. It returns errCANotFound only when
// both files are missing.
func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)

	switch {
	case certErr == nil && keyErr == nil:
		warnLooseKeyPerms(keyPath)
		ca, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errCAInvalid, err)
		}
		return ca, nil
	case errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist):
		return nil, errCANotFound
	case certErr != nil && !errors.Is(certErr, fs.ErrNotExist):
		return nil, fmt.Errorf("failed to read CA cert: %w", certErr)
	case keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist):
		return nil, fmt.Errorf("failed to read CA key: %w", keyErr)
	case certErr != nil:
		return nil, fmt.Errorf("%w: %s is missing but the CA key exists; remove %s to regenerate", errCAKeyOnly, certPath, filepath.Dir(certPath))
	default:
		return nil, fmt.Errorf("%w: %s is missing but the CA cert exists; remove %s to regenerate", errCAIncomplete, keyPath, filepath.Dir(keyPath))
	}
}

// waitForCA loads a CA that another process may be in the middle of
// creating, giving up with the last error after a short wait.
func waitForCA(certPath, keyPath string) (*CA, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		ca, err := loadCA(certPath, keyPath)
		if err == nil || time.Now().After(deadline) {
			return ca, err
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// caFilesStale reports whether at least one CA file exists and every one
// that does is older than staleKeyAge.
func caFilesStale(paths ...string) bool {
	found := false
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) < staleKeyAge {
			return false
		}
		found = true
	}
	return found
}

// removeStaleKey removes an orphaned CA key older than staleKeyAge and
// reports whether it did.
func removeStaleKey(keyPath string) bool {
	info, err := os.Lstat(keyPath)
	if err != nil || time.Since(info.ModTime()) < staleKeyAge {
		return false
	}
	// Recheck right before removing, so a key a concurrent creator just
	// wrote in its place is left alone.
	if cur, err := os.Lstat(keyPath); err != nil || !os.SameFile(cur, info) || !cur.ModTime().Equal(info.ModTime()) {
		return false
	}
	if os.Remove(keyPath) != nil {
		return false
	}
	fmt.Fprintf(os.Stderr, "Removed orphaned CA key %s (no matching cert); generating a new CA\n", keyPath)
	return true
}

// linkFn creates hard links. Overridable for testing.
var linkFn = os.Link

// writeFileExclusive atomically creates path with data at 0600. It returns
// false, without error, if path already exists. The data is written to a
// temp file and hard-linked into place, so readers never see a partial file.
// Where hard links are unsupported it falls back to an exclusive create and
// direct write; readers treat the resulting partial file as retryable.
func writeFileExclusive(path string, data []byte) (bool, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := linkFn(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return writeFileExclusiveDirect(path, data)
	}
	return true, nil
}

// writeFileExclusiveDirect creates path with O_EXCL and writes data to it.
func writeFileExclusiveDirect(path string, data []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return false, err
	}
	return true, nil
}

// warnLooseKeyPerms warns on stderr if the CA key is accessible to group or
// others: anyone who can read it can mint certs this proxy's clients trust.
func warnLooseKeyPerms(keyPath string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		return
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		fmt.Fprintf(os.Stderr, "Warning: CA key %s has mode %o and is accessible to other users; run: chmod 600 %s\n", keyPath, perm, keyPath)
	}
}

// GenerateHostCert creates a short-lived leaf certificate for the given host,
// signed by the CA. Certs are not persisted to disk.
func (ca *CA) GenerateHostCert(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign host cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal host key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS cert: %w", err)
	}

	return &tlsCert, nil
}

// keyPEM is only used during generation so we can persist it.
type caWithKey struct {
	*CA
	keyPEM []byte
}

func generateCA() (*caWithKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "nokey local proxy CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &caWithKey{
		CA: &CA{
			Cert:    cert,
			Key:     key,
			CertPEM: certPEM,
		},
		keyPEM: keyPEM,
	}, nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("CA cert is not a CA certificate")
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("CA key does not match CA cert")
	}

	return &CA{
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
	}, nil
}
