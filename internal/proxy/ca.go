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
	"slices"
	"strings"
	"time"

	"github.com/nokey-ai/nokey/internal/filelock"
)

// CA holds the local proxy CA certificate and key used for MITM HTTPS interception.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.PrivateKey
	CertPEM []byte
}

// KeyStore is where the CA key is kept: the OS keyring, not a file. Once
// the certificate is trusted, whoever reads the key can sign for the hosts
// the CA covers, and a file is readable by every program running as the
// user.
type KeyStore interface {
	// CAKey returns the stored key in PEM, or "" when there is none.
	CAKey() (string, error)
	SetCAKey(keyPEM string) error
}

const (
	// caLifetime is how long a CA is valid. It is short because a leaked
	// key is good for as long as the certificate is; a new CA is made when
	// this one nears expiry.
	caLifetime = 90 * 24 * time.Hour
	// caRenewBefore is how close to expiry a CA may get before it is
	// replaced, so a proxy started today doesn't outlive its CA.
	caRenewBefore = 7 * 24 * time.Hour
	// noDNSName is the one DNS name a CA for IP-only rules may sign. A CA
	// with no permitted DNS names at all would be free to sign any.
	noDNSName = "nokey.invalid"
)

// LoadOrCreateCA returns the CA for a proxy serving hosts, the host
// patterns of the proxy rules. The certificate is in configDir/ca/ and the
// key in keys.
//
// The CA carries name constraints for hosts, so a stolen key can't sign
// for any other name. A CA that can't serve as that (none yet, a rule host
// it doesn't cover, near expiry, key lost, or an old one whose key was a
// file) is replaced, and stderr says so: whatever trusted the old
// certificate has to trust the new one. A failure to read the certificate
// or the keyring is returned instead, since the CA behind it may be fine.
func LoadOrCreateCA(configDir string, keys KeyStore, hosts []string) (*CA, error) {
	dns, ips, err := nameConstraints(hosts)
	if err != nil {
		return nil, err
	}

	caDir := filepath.Join(configDir, "ca")
	certPath := filepath.Join(caDir, "ca-cert.pem")
	legacyKeyPath := filepath.Join(caDir, "ca-key.pem")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Concurrent runs (several `nokey exec --isolate`, say) must end up
	// with one CA: a run holding a CA other than the one on disk would
	// serve certificates its clients reject.
	unlock, err := lockCADir(caDir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	ca, replaced, err := loadCA(certPath, legacyKeyPath, keys, dns, ips)
	if err != nil || ca != nil {
		return ca, err
	}

	gen, err := generateCA(dns, ips)
	if err != nil {
		return nil, err
	}
	// Key first: a crash before the cert is written leaves a key that
	// doesn't match the old cert, which the next run replaces again.
	if err := keys.SetCAKey(string(gen.keyPEM)); err != nil {
		return nil, fmt.Errorf("failed to store CA key in the keyring: %w", err)
	}
	if err := writeFileAtomic(certPath, gen.CertPEM); err != nil {
		return nil, fmt.Errorf("failed to write CA cert: %w", err)
	}
	legacyKey := false
	if err := os.Remove(legacyKeyPath); err == nil {
		legacyKey = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to remove the old unencrypted CA key: %w", err)
	}

	if replaced != "" {
		fmt.Fprintf(os.Stderr, "nokey: made a new proxy CA because %s.\n  Anything that trusted the old certificate must trust the new one: %s\n", replaced, certPath)
	}
	if legacyKey {
		fmt.Fprintf(os.Stderr, "  The old CA could sign for any host and its key was an unencrypted file, readable by every program running as you.\n  If you added it to a system trust store, remove it there (it is named %q).\n", caCommonName)
	}
	return gen.CA, nil
}

// loadCA returns the stored CA if it can serve dns and ips. Otherwise ca
// is nil and replaced says why a new one is needed, or is "" when there
// was no CA at all.
func loadCA(certPath, legacyKeyPath string, keys KeyStore, dns []string, ips []*net.IPNet) (ca *CA, replaced string, err error) {
	certPEM, certErr := os.ReadFile(certPath)
	if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("failed to read CA cert: %w", certErr)
	}
	keyPEM, err := keys.CAKey()
	if err != nil {
		return nil, "", fmt.Errorf("failed to read CA key from the keyring: %w", err)
	}
	_, legacyErr := os.Lstat(legacyKeyPath)

	switch {
	case legacyErr == nil:
		return nil, "the old one kept its key in an unencrypted file", nil
	case certErr != nil && keyPEM == "":
		return nil, "", nil
	case certErr != nil:
		return nil, "its certificate is missing", nil
	case keyPEM == "":
		return nil, "its key is not in the keyring", nil
	}

	ca, err = parseCA(certPEM, []byte(keyPEM))
	if err != nil {
		return nil, fmt.Sprintf("the stored one is unusable (%v)", err), nil
	}
	if why := unfit(ca.Cert, dns, ips, time.Now()); why != "" {
		return nil, why, nil
	}
	return ca, "", nil
}

// unfit says why cert can't be the CA for dns and ips, or "" if it can.
func unfit(cert *x509.Certificate, dns []string, ips []*net.IPNet, now time.Time) string {
	if !cert.PermittedDNSDomainsCritical || len(cert.PermittedDNSDomains) == 0 {
		return "the old one could sign for any host"
	}
	if now.After(cert.NotAfter.Add(-caRenewBefore)) {
		return fmt.Sprintf("the old one expires on %s", cert.NotAfter.Format(time.DateOnly))
	}
	for _, name := range dns {
		if !slices.ContainsFunc(cert.PermittedDNSDomains, func(permitted string) bool { return dnsCovers(permitted, name) }) {
			return fmt.Sprintf("the old one does not cover the proxy rule host %q", name)
		}
	}
	for _, ip := range ips {
		if !slices.ContainsFunc(cert.PermittedIPRanges, func(permitted *net.IPNet) bool { return permitted.Contains(ip.IP) }) {
			return fmt.Sprintf("the old one does not cover the proxy rule host %q", ip.IP)
		}
	}
	return ""
}

// dnsCovers reports whether the name constraint permitted allows name,
// itself a host name or a constraint from nameConstraints. A constraint
// with a leading dot allows subdomains only; one without allows the name
// and its subdomains.
func dnsCovers(permitted, name string) bool {
	if strings.HasPrefix(permitted, ".") {
		return strings.HasSuffix(name, permitted)
	}
	return name == permitted || strings.HasSuffix(name, "."+permitted)
}

// nameConstraints turns proxy rule host patterns into the names a CA may
// sign for. A plain name or IP address is itself. A glob pattern becomes
// the domain after its last wildcard, cut at a label: "*.example.com" and
// "api-*.example.com" both give ".example.com", every subdomain of
// example.com. A pattern with no fixed domain to cut to ("*", "api.*") is
// refused, because the only CA that could serve it is an unconstrained one.
func nameConstraints(hosts []string) (dns []string, ips []*net.IPNet, err error) {
	if len(hosts) == 0 {
		return nil, nil, errors.New("the proxy CA is limited to the hosts of the proxy rules, and there are none")
	}
	for _, host := range hosts {
		name := strings.ToLower(strings.TrimSpace(host))
		wildcard := strings.LastIndexAny(name, `*?[]\`)
		if wildcard < 0 {
			if ip := net.ParseIP(name); ip != nil {
				ips = append(ips, hostNet(ip))
			} else {
				dns = append(dns, name)
			}
			continue
		}
		fixed := name[wildcard+1:]
		dot := strings.Index(fixed, ".")
		if dot < 0 || dot == len(fixed)-1 {
			return nil, nil, fmt.Errorf("proxy rule host %q does not end in a fixed domain, so the proxy CA can't be limited to it; end the pattern with one (\"*.example.com\") or list the hosts", host)
		}
		dns = append(dns, fixed[dot:])
	}
	slices.Sort(dns)
	dns = slices.Compact(dns)
	slices.SortFunc(ips, func(a, b *net.IPNet) int { return strings.Compare(a.String(), b.String()) })
	ips = slices.CompactFunc(ips, func(a, b *net.IPNet) bool { return a.String() == b.String() })
	return dns, ips, nil
}

// hostNet is the network holding only ip.
func hostNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// lockCADir takes the lock that serializes CA loading and creation across
// processes and returns the function that releases it. The lock file is
// never removed, for the reason given at audit's lock.
func lockCADir(caDir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(caDir, "ca.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open CA lock: %w", err)
	}
	if err := filelock.Lock(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to lock CA directory: %w", err)
	}
	return func() {
		_ = filelock.Unlock(f)
		_ = f.Close()
	}, nil
}

// writeFileAtomic replaces path with data at 0600. The data is written to
// a temp file and renamed into place, so readers never see a partial file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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

// caCommonName is the CA's subject, the name trust stores list it under.
const caCommonName = "nokey local proxy CA"

// generateCA makes a CA that may sign only for dns and ips, and only
// server certificates.
func generateCA(dns []string, ips []*net.IPNet) (*caWithKey, error) {
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
		Subject:               pkix.Name{CommonName: caCommonName},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,

		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         dns,
		PermittedIPRanges:           ips,
	}
	// Constraints bind one kind of name at a time: with none for a kind,
	// every name of that kind is allowed. So a kind no rule uses is shut.
	if len(dns) == 0 {
		template.PermittedDNSDomains = []string{noDNSName}
	}
	if len(ips) == 0 {
		template.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
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
