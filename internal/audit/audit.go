package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nokey-ai/nokey/internal/config"
	nokeyKeyring "github.com/nokey-ai/nokey/internal/keyring"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// AuditLogKey is the keyring key where encrypted audit log is stored
	AuditLogKey = "__nokey_audit_log__"

	// AuditEncryptionKeyKey is where the encryption key for audit logs is stored
	AuditEncryptionKeyKey = "__nokey_audit_encryption_key__"

	// AuditChainHeadKey is the keyring key for the hash chain head checkpoint
	AuditChainHeadKey = "__nokey_audit_chain_head__"

	auditLogFileName  = "audit.log"
	hmacDerivationTag = "nokey-audit-chain-v1"

	// zeroHMAC is the prev_hmac for the first entry in a chain
	zeroHMAC = "0000000000000000000000000000000000000000000000000000000000000000"
)

// AuditLogDir returns the directory for audit log files. Overridable for testing.
var AuditLogDir = config.ConfigDir

// storedEntry wraps an AuditEntry with chain metadata. Internal to storage.
type storedEntry struct {
	Entry    AuditEntry `json:"entry"`
	PrevHMAC string     `json:"prev_hmac"`
}

// chainHead is persisted in the keyring to detect truncation.
type chainHead struct {
	HMAC  string `json:"hmac"`
	Count int    `json:"count"`
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp    time.Time `json:"timestamp"`       // UTC timestamp
	SecretNames  []string  `json:"secret_names"`    // Names of secrets accessed (never values)
	Command      string    `json:"command"`         // Command executed
	AuthMethod   string    `json:"auth_method"`     // "pin", "oauth", "both", "none"
	Success      bool      `json:"success"`         // Whether operation succeeded
	User         string    `json:"user"`            // OS username
	Hostname     string    `json:"hostname"`        // Machine hostname
	PID          int       `json:"pid"`             // Process ID
	ErrorMessage string    `json:"error,omitempty"` // Error message if failed
	Operation    string    `json:"operation"`       // "exec", "set", "delete", "import", "auth"
}

// AuditLog contains all audit entries and any integrity warnings.
type AuditLog struct {
	Entries  []AuditEntry `json:"entries"`
	Warnings []string     `json:"-"`
}

// NewAuditEntry creates a new audit entry with system info populated
func NewAuditEntry(operation, command, authMethod string, secretNames []string, success bool, errorMsg string) *AuditEntry {
	// Get system information
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	hostname := "unknown"
	if h, err := os.Hostname(); err == nil {
		hostname = h
	}

	return &AuditEntry{
		Timestamp:    time.Now().UTC(),
		SecretNames:  secretNames,
		Command:      command,
		AuthMethod:   authMethod,
		Success:      success,
		User:         username,
		Hostname:     hostname,
		PID:          os.Getpid(),
		ErrorMessage: errorMsg,
		Operation:    operation,
	}
}

// Load reads the audit log from the encrypted file with chain verification.
func Load(store *nokeyKeyring.Store) (*AuditLog, error) {
	encKey, err := getOrCreateEncryptionKey(store)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %w", err)
	}
	hmacKey := deriveHMACKey(encKey)

	head, err := loadChainHead(store)
	if err != nil {
		return nil, err
	}

	filePath, err := auditLogPath()
	if err != nil {
		return nil, err
	}

	return readAndVerifyFile(filePath, encKey, hmacKey, head)
}

// Record appends a new entry to the audit log file with chain integrity.
// maxEntries and retentionDays control lazy compaction (triggered at 2x maxEntries).
func Record(store *nokeyKeyring.Store, entry *AuditEntry, maxEntries, retentionDays int) error {
	encKey, err := getOrCreateEncryptionKey(store)
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}
	hmacKey := deriveHMACKey(encKey)

	head, err := loadChainHead(store)
	if err != nil {
		return err
	}

	filePath, err := auditLogPath()
	if err != nil {
		return err
	}

	// Determine prev HMAC for this entry
	prevHMAC := head.HMAC
	if prevHMAC == "" {
		prevHMAC = zeroHMAC
	}

	// Build stored entry
	se := storedEntry{Entry: *entry, PrevHMAC: prevHMAC}

	lineBytes, err := encryptEntry(&se, encKey)
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Append to file
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	if _, err := f.Write(append(lineBytes, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("failed to write audit entry: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close audit log: %w", err)
	}

	// Update chain head
	newHMAC := computeLineHMAC(hmacKey, lineBytes)
	head.HMAC = newHMAC
	head.Count++

	return saveChainHead(store, head)
}

// Clear removes the audit log file and chain head from keyring.
func Clear(store *nokeyKeyring.Store) error {
	filePath, err := auditLogPath()
	if err != nil {
		return err
	}

	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove audit log: %w", err)
	}

	// Clean up chain head
	_ = store.Delete(AuditChainHeadKey)
	// Clean up old keyring format if present
	_ = store.Delete(AuditLogKey)

	return nil
}

// encryptEntry serializes and encrypts a storedEntry, returning base64-encoded bytes.
func encryptEntry(se *storedEntry, encKey *[32]byte) ([]byte, error) {
	plaintext, err := json.Marshal(se)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize audit entry: %w", err)
	}
	ciphertext, err := encrypt(plaintext, encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt audit entry: %w", err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)
	return encoded, nil
}

// readAndVerifyFile reads and verifies the audit log file against the chain head.
func readAndVerifyFile(filePath string, encKey *[32]byte, hmacKey []byte, head *chainHead) (*AuditLog, error) {
	f, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &AuditLog{Entries: []AuditEntry{}}, nil
		}
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	var entries []AuditEntry
	var warnings []string
	expectedPrevHMAC := zeroHMAC
	var lastLineHMAC string
	lineCount := 0

	scanner := bufio.NewScanner(f)
	// Allow up to 1MB per line for large encrypted entries
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		lineCount++

		// Compute HMAC of this line
		lineHMAC := computeLineHMAC(hmacKey, line)

		// Decode and decrypt
		ciphertext, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: base64 decode failed", lineCount))
			expectedPrevHMAC = lineHMAC
			lastLineHMAC = lineHMAC
			continue
		}

		plaintext, err := decrypt(ciphertext, encKey)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: decryption failed (possible tampering)", lineCount))
			expectedPrevHMAC = lineHMAC
			lastLineHMAC = lineHMAC
			continue
		}

		var se storedEntry
		if err := json.Unmarshal(plaintext, &se); err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: JSON parse failed", lineCount))
			expectedPrevHMAC = lineHMAC
			lastLineHMAC = lineHMAC
			continue
		}

		// Verify chain link
		if se.PrevHMAC != expectedPrevHMAC {
			warnings = append(warnings, fmt.Sprintf("line %d: chain break detected (expected prev_hmac %s..., got %s...)",
				lineCount, truncHex(expectedPrevHMAC), truncHex(se.PrevHMAC)))
		}

		entries = append(entries, se.Entry)
		expectedPrevHMAC = lineHMAC
		lastLineHMAC = lineHMAC
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	// Verify against chain head checkpoint
	if head.Count > 0 {
		if lineCount < head.Count {
			warnings = append(warnings, fmt.Sprintf("truncation detected: expected %d entries, found %d", head.Count, lineCount))
		}
		if lineCount > 0 && lastLineHMAC != head.HMAC {
			if lineCount == head.Count {
				warnings = append(warnings, "chain head HMAC mismatch (possible tampering of last entry)")
			}
		}
	}

	return &AuditLog{Entries: entries, Warnings: warnings}, nil
}

// ApplyRetentionPolicy removes old entries based on count and age
func (a *AuditLog) ApplyRetentionPolicy(maxEntries int, retentionDays int) {
	if len(a.Entries) == 0 {
		return
	}

	// Sort by timestamp (oldest first)
	sort.Slice(a.Entries, func(i, j int) bool {
		return a.Entries[i].Timestamp.Before(a.Entries[j].Timestamp)
	})

	// Remove entries older than retention period
	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays)
	validEntries := make([]AuditEntry, 0, len(a.Entries))
	for _, entry := range a.Entries {
		if entry.Timestamp.After(cutoffDate) {
			validEntries = append(validEntries, entry)
		}
	}

	// Keep only the most recent maxEntries
	if len(validEntries) > maxEntries {
		validEntries = validEntries[len(validEntries)-maxEntries:]
	}

	a.Entries = validEntries
}

// Filter returns entries matching the criteria
type FilterOptions struct {
	Since      *time.Time
	SecretName string
	Command    string
	Operation  string
	Limit      int
}

func (a *AuditLog) Filter(opts FilterOptions) []AuditEntry {
	filtered := make([]AuditEntry, 0)

	for _, entry := range a.Entries {
		// Filter by time
		if opts.Since != nil && entry.Timestamp.Before(*opts.Since) {
			continue
		}

		// Filter by secret name
		if opts.SecretName != "" {
			found := false
			for _, name := range entry.SecretNames {
				if name == opts.SecretName {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Filter by command
		if opts.Command != "" && entry.Command != opts.Command {
			continue
		}

		// Filter by operation
		if opts.Operation != "" && entry.Operation != opts.Operation {
			continue
		}

		filtered = append(filtered, entry)
	}

	// Sort by timestamp (most recent first)
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.After(filtered[j].Timestamp)
	})

	// Apply limit
	if opts.Limit > 0 && len(filtered) > opts.Limit {
		filtered = filtered[:opts.Limit]
	}

	return filtered
}

// ExportJSON exports the audit log as JSON
func (a *AuditLog) ExportJSON(entries []AuditEntry) ([]byte, error) {
	return json.MarshalIndent(entries, "", "  ")
}

// ExportCSV exports the audit log as CSV
func (a *AuditLog) ExportCSV(entries []AuditEntry) ([]byte, error) {
	var b strings.Builder

	// CSV header
	b.WriteString("Timestamp,Operation,Command,Secrets,AuthMethod,Success,User,Hostname,PID,Error\n")

	for _, entry := range entries {
		secretsStr := ""
		if len(entry.SecretNames) > 0 {
			secretsJSON, _ := json.Marshal(entry.SecretNames)
			secretsStr = string(secretsJSON)
		}

		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%t,%s,%s,%d,%s\n",
			entry.Timestamp.Format(time.RFC3339),
			entry.Operation,
			csvEscape(entry.Command),
			csvEscape(secretsStr),
			entry.AuthMethod,
			entry.Success,
			csvEscape(entry.User),
			csvEscape(entry.Hostname),
			entry.PID,
			csvEscape(entry.ErrorMessage),
		)
	}

	return []byte(b.String()), nil
}

// csvEscape escapes a string for CSV output
func csvEscape(s string) string {
	// If contains comma, quote, or newline, wrap in quotes and escape quotes
	needsQuotes := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' {
			needsQuotes = true
			break
		}
	}

	if !needsQuotes {
		return s
	}

	// Escape quotes by doubling them
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, c := range s {
		if c == '"' {
			b.WriteString("\"\"")
		} else {
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')

	return b.String()
}

// auditLogPath returns the full path to the audit log file.
func auditLogPath() (string, error) {
	dir, err := AuditLogDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, auditLogFileName), nil
}

// truncHex returns the first 8 chars of a hex string for display.
func truncHex(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// deriveHMACKey derives a separate HMAC key from the encryption key.
func deriveHMACKey(encKey *[32]byte) []byte {
	mac := hmac.New(sha256.New, encKey[:])
	mac.Write([]byte(hmacDerivationTag))
	return mac.Sum(nil)
}

// computeLineHMAC returns the hex-encoded HMAC-SHA256 of lineBytes.
func computeLineHMAC(hmacKey, lineBytes []byte) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(lineBytes)
	return hex.EncodeToString(mac.Sum(nil))
}

// loadChainHead reads the chain head checkpoint from the keyring.
// Returns a zero-value chainHead if not found.
func loadChainHead(store *nokeyKeyring.Store) (*chainHead, error) {
	data, err := store.Get(AuditChainHeadKey)
	if err != nil {
		if nokeyKeyring.IsNotFound(err) {
			return &chainHead{}, nil
		}
		return nil, fmt.Errorf("failed to load chain head: %w", err)
	}
	var head chainHead
	if err := json.Unmarshal([]byte(data), &head); err != nil {
		return nil, fmt.Errorf("failed to parse chain head: %w", err)
	}
	return &head, nil
}

// saveChainHead writes the chain head checkpoint to the keyring.
func saveChainHead(store *nokeyKeyring.Store, head *chainHead) error {
	data, err := json.Marshal(head)
	if err != nil {
		return fmt.Errorf("failed to serialize chain head: %w", err)
	}
	if err := store.Set(AuditChainHeadKey, string(data)); err != nil {
		return fmt.Errorf("failed to save chain head: %w", err)
	}
	return nil
}

// getOrCreateEncryptionKey retrieves or creates the encryption key for audit logs
func getOrCreateEncryptionKey(store *nokeyKeyring.Store) (*[32]byte, error) {
	// Try to load existing key
	keyStr, err := store.Get(AuditEncryptionKeyKey)
	if err == nil {
		// Key exists — try base64 decode first (new format)
		decoded, decErr := base64.StdEncoding.DecodeString(keyStr)
		if decErr == nil && len(decoded) == 32 {
			var key [32]byte
			copy(key[:], decoded)
			return &key, nil
		}

		// Fall back to raw bytes (legacy format — may have null-byte issues)
		if len(keyStr) == 32 {
			var key [32]byte
			copy(key[:], []byte(keyStr))
			// Re-store as base64 for future safety
			_ = store.Set(AuditEncryptionKeyKey, base64.StdEncoding.EncodeToString(key[:]))
			return &key, nil
		}

		return nil, fmt.Errorf("invalid encryption key length")
	}

	// Key doesn't exist, create new one
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Store as base64 to prevent null-byte truncation
	if err := store.Set(AuditEncryptionKeyKey, base64.StdEncoding.EncodeToString(key[:])); err != nil {
		return nil, fmt.Errorf("failed to store encryption key: %w", err)
	}

	return &key, nil
}

// encrypt encrypts data using NaCl secretbox
func encrypt(data []byte, key *[32]byte) ([]byte, error) {
	// Generate random nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	// Encrypt
	encrypted := secretbox.Seal(nonce[:], data, &nonce, key)
	return encrypted, nil
}

// decrypt decrypts data using NaCl secretbox
func decrypt(data []byte, key *[32]byte) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce
	var nonce [24]byte
	copy(nonce[:], data[:24])

	// Decrypt
	decrypted, ok := secretbox.Open(nil, data[24:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}
