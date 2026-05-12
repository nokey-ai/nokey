package proxy

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CertFingerprint struct {
	SHA256    string    `json:"sha256"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type CertTracker struct {
	mu           sync.Mutex
	fingerprints map[string]*CertFingerprint // host -> fingerprint
	persistPath  string
	auditFn      AuditFunc
}

func NewCertTracker(persistPath string, auditFn AuditFunc) *CertTracker {
	ct := &CertTracker{
		fingerprints: make(map[string]*CertFingerprint),
		persistPath:  persistPath,
		auditFn:      auditFn,
	}
	ct.load()
	return ct
}

func (ct *CertTracker) CheckUpstream(host string, hostPort string) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", hostPort,
		&tls.Config{InsecureSkipVerify: false},
	)
	if err != nil {
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}

	fp := sha256.Sum256(certs[0].Raw)
	fpHex := hex.EncodeToString(fp[:])

	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now().UTC()
	existing, known := ct.fingerprints[host]

	if !known {
		ct.fingerprints[host] = &CertFingerprint{
			SHA256:    fpHex,
			FirstSeen: now,
			LastSeen:  now,
		}
		_ = ct.saveLocked()
		return
	}

	if existing.SHA256 != fpHex {
		if ct.auditFn != nil {
			msg := fmt.Sprintf("certificate changed: was %s...%s, now %s...%s",
				existing.SHA256[:8], existing.SHA256[len(existing.SHA256)-8:],
				fpHex[:8], fpHex[len(fpHex)-8:])
			ct.auditFn("proxy:cert_change", host, "", false, msg)
		}
		ct.fingerprints[host] = &CertFingerprint{
			SHA256:    fpHex,
			FirstSeen: now,
			LastSeen:  now,
		}
		_ = ct.saveLocked()
		return
	}

	existing.LastSeen = now
}

func (ct *CertTracker) load() {
	if ct.persistPath == "" {
		return
	}
	data, err := os.ReadFile(ct.persistPath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &ct.fingerprints)
}

func (ct *CertTracker) saveLocked() error {
	if ct.persistPath == "" {
		return nil
	}
	dir := filepath.Dir(ct.persistPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ct.fingerprints, "", "  ")
	if err != nil {
		return err
	}
	tmp := ct.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, ct.persistPath)
}

func (ct *CertTracker) KnownHosts() map[string]*CertFingerprint {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	cp := make(map[string]*CertFingerprint, len(ct.fingerprints))
	for k, v := range ct.fingerprints {
		entry := *v
		cp[k] = &entry
	}
	return cp
}
