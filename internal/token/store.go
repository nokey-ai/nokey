package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxTTLSecs = 3600
	tokenBytes = 32 // 64 hex chars
)

// Token represents an access lease for one or more secrets.
type Token struct {
	ID        string
	Secrets   []string // which secrets this token authorizes
	MaxUses   int      // 0 = unlimited (TTL-only)
	UsesLeft  int
	ExpiresAt time.Time
	MintedAt  time.Time
	MintedFor string // command pattern or "*" for any
}

// MintRequest contains the parameters for minting a new token.
type MintRequest struct {
	Secrets   []string
	TTLSecs   int    // max 3600
	MaxUses   int    // 0 = unlimited
	MintedFor string // command pattern or "*"
}

// ValidationResult describes whether a token is valid for the requested operation.
type ValidationResult struct {
	Valid  bool
	Reason string // "ok", "expired", "exhausted", "not_found", "wrong_secret", "wrong_command"
	// MintedFor is the token's command pattern, set with "wrong_command"
	// so the caller can say what the token is for.
	MintedFor string
}

// Store is an in-memory, session-scoped token store. Tokens die with the process.
type Store struct {
	mu     sync.RWMutex
	tokens map[string]*Token
	now    func() time.Time // injectable clock for testing
}

// NewStore creates an empty token store.
func NewStore() *Store {
	return &Store{
		tokens: make(map[string]*Token),
		now:    time.Now,
	}
}

// Validate reports whether Mint would accept the request, so callers can
// reject a bad request before asking the user to approve it.
func (req MintRequest) Validate() error {
	if len(req.Secrets) == 0 {
		return fmt.Errorf("at least one secret is required")
	}
	if req.TTLSecs <= 0 {
		return fmt.Errorf("ttl_seconds must be positive")
	}
	if req.TTLSecs > maxTTLSecs {
		return fmt.Errorf("ttl_seconds exceeds maximum of %d", maxTTLSecs)
	}
	if req.MaxUses < 0 {
		return fmt.Errorf("max_uses must be non-negative")
	}
	if _, err := path.Match(req.MintedFor, ""); err != nil {
		return fmt.Errorf("invalid 'for' pattern %q: %w", req.MintedFor, err)
	}
	return nil
}

// Mint creates a new access lease token. Returns an error if the request is invalid.
func (s *Store) Mint(req MintRequest) (*Token, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := s.now()
	tok := &Token{
		ID:        id,
		Secrets:   req.Secrets,
		MaxUses:   req.MaxUses,
		UsesLeft:  req.MaxUses,
		ExpiresAt: now.Add(time.Duration(req.TTLSecs) * time.Second),
		MintedAt:  now,
		MintedFor: req.MintedFor,
	}
	if tok.MintedFor == "" {
		tok.MintedFor = "*"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup()
	s.tokens[id] = tok

	return tok, nil
}

// Validate checks whether a token is valid for the requested secrets without consuming a use.
func (s *Store) Validate(id string, secrets []string) ValidationResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.validate(id, secrets)
}

// Use is UseFor with an unknown command: only tokens minted for "*" pass.
func (s *Store) Use(id string, secrets []string) ValidationResult {
	return s.UseFor(id, "*", secrets)
}

// UseFor validates the token for running command with secrets and then
// consumes one use. The token's MintedFor pattern is matched against the
// command's base name, as policy rules are. Auto-removes exhausted tokens.
func (s *Store) UseFor(id, command string, secrets []string) ValidationResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := s.validate(id, secrets)
	if !result.Valid {
		return result
	}

	tok := s.tokens[id]
	if !matchesCommand(tok.MintedFor, command) {
		return ValidationResult{Valid: false, Reason: "wrong_command", MintedFor: tok.MintedFor}
	}

	if tok.MaxUses > 0 {
		tok.UsesLeft--
		if tok.UsesLeft <= 0 {
			delete(s.tokens, id)
		}
	}

	return result
}

// Revoke removes a token by ID. Returns true if the token existed.
func (s *Store) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tokens[id]; ok {
		delete(s.tokens, id)
		return true
	}
	return false
}

// List returns all active (non-expired) tokens.
func (s *Store) List() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup()

	result := make([]Token, 0, len(s.tokens))
	for _, tok := range s.tokens {
		result = append(result, *tok)
	}
	return result
}

// validate checks a token without locking (caller must hold at least RLock).
func (s *Store) validate(id string, secrets []string) ValidationResult {
	tok, ok := s.tokens[id]
	if !ok {
		return ValidationResult{Valid: false, Reason: "not_found"}
	}

	if s.now().After(tok.ExpiresAt) {
		return ValidationResult{Valid: false, Reason: "expired"}
	}

	if tok.MaxUses > 0 && tok.UsesLeft <= 0 {
		return ValidationResult{Valid: false, Reason: "exhausted"}
	}

	// Check that the token covers all requested secrets.
	allowed := make(map[string]bool, len(tok.Secrets))
	for _, sec := range tok.Secrets {
		allowed[sec] = true
	}
	for _, sec := range secrets {
		if !allowed[sec] {
			return ValidationResult{Valid: false, Reason: "wrong_secret"}
		}
	}

	return ValidationResult{Valid: true, Reason: "ok"}
}

// cleanup removes expired tokens (caller must hold write lock).
func (s *Store) cleanup() {
	now := s.now()
	for id, tok := range s.tokens {
		if now.After(tok.ExpiresAt) {
			delete(s.tokens, id)
		}
	}
}

// matchesCommand reports whether a MintedFor pattern covers command.
func matchesCommand(pattern, command string) bool {
	if pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, filepath.Base(command))
	return err == nil && matched
}

func generateID() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
