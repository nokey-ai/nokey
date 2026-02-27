package token

import (
	"sync"
	"testing"
	"time"
)

func newTestStore(now time.Time) *Store {
	s := NewStore()
	s.now = func() time.Time { return now }
	return s
}

func TestMint(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s := newTestStore(now)

	tok, err := s.Mint(MintRequest{
		Secrets:   []string{"GITHUB_TOKEN"},
		TTLSecs:   300,
		MaxUses:   5,
		MintedFor: "gh",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tok.ID) != 64 {
		t.Errorf("expected 64-char hex ID, got %d chars", len(tok.ID))
	}
	if tok.MaxUses != 5 || tok.UsesLeft != 5 {
		t.Errorf("expected 5/5 uses, got %d/%d", tok.MaxUses, tok.UsesLeft)
	}
	if tok.MintedFor != "gh" {
		t.Errorf("expected MintedFor=gh, got %q", tok.MintedFor)
	}
	if !tok.ExpiresAt.Equal(now.Add(300 * time.Second)) {
		t.Errorf("unexpected expiry: %v", tok.ExpiresAt)
	}
}

func TestMintDefaultMintedFor(t *testing.T) {
	s := newTestStore(time.Now())
	tok, err := s.Mint(MintRequest{Secrets: []string{"S"}, TTLSecs: 60})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.MintedFor != "*" {
		t.Errorf("expected default MintedFor=*, got %q", tok.MintedFor)
	}
}

func TestMintValidation(t *testing.T) {
	s := newTestStore(time.Now())

	tests := []struct {
		name string
		req  MintRequest
	}{
		{"no secrets", MintRequest{TTLSecs: 60}},
		{"zero TTL", MintRequest{Secrets: []string{"S"}, TTLSecs: 0}},
		{"negative TTL", MintRequest{Secrets: []string{"S"}, TTLSecs: -1}},
		{"TTL exceeds max", MintRequest{Secrets: []string{"S"}, TTLSecs: 7200}},
		{"negative max_uses", MintRequest{Secrets: []string{"S"}, TTLSecs: 60, MaxUses: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Mint(tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestMintMaxTTLBoundary(t *testing.T) {
	s := newTestStore(time.Now())

	// Exactly max TTL should succeed
	_, err := s.Mint(MintRequest{Secrets: []string{"S"}, TTLSecs: 3600})
	if err != nil {
		t.Fatalf("expected success at max TTL, got: %v", err)
	}

	// One over should fail
	_, err = s.Mint(MintRequest{Secrets: []string{"S"}, TTLSecs: 3601})
	if err == nil {
		t.Fatal("expected error for TTL > max")
	}
}

func TestValidateValid(t *testing.T) {
	now := time.Now()
	s := newTestStore(now)

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A", "B"}, TTLSecs: 60, MaxUses: 3})

	result := s.Validate(tok.ID, []string{"A"})
	if !result.Valid || result.Reason != "ok" {
		t.Errorf("expected valid, got %+v", result)
	}

	result = s.Validate(tok.ID, []string{"A", "B"})
	if !result.Valid {
		t.Errorf("expected valid for both secrets, got %+v", result)
	}
}

func TestValidateExpired(t *testing.T) {
	now := time.Now()
	s := newTestStore(now)

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60})

	// Advance clock past expiry
	s.now = func() time.Time { return now.Add(61 * time.Second) }

	result := s.Validate(tok.ID, []string{"A"})
	if result.Valid || result.Reason != "expired" {
		t.Errorf("expected expired, got %+v", result)
	}
}

func TestValidateExhausted(t *testing.T) {
	now := time.Now()
	s := newTestStore(now)

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60, MaxUses: 1})

	// Use up the single use
	s.Use(tok.ID, []string{"A"})

	// Token should be auto-removed
	result := s.Validate(tok.ID, []string{"A"})
	if result.Valid || result.Reason != "not_found" {
		t.Errorf("expected not_found after exhaustion, got %+v", result)
	}
}

func TestValidateWrongSecret(t *testing.T) {
	s := newTestStore(time.Now())

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60})

	result := s.Validate(tok.ID, []string{"B"})
	if result.Valid || result.Reason != "wrong_secret" {
		t.Errorf("expected wrong_secret, got %+v", result)
	}
}

func TestValidateNotFound(t *testing.T) {
	s := newTestStore(time.Now())

	result := s.Validate("nonexistent", []string{"A"})
	if result.Valid || result.Reason != "not_found" {
		t.Errorf("expected not_found, got %+v", result)
	}
}

func TestUseDecrementsCounter(t *testing.T) {
	s := newTestStore(time.Now())

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60, MaxUses: 3})

	for i := 0; i < 3; i++ {
		result := s.Use(tok.ID, []string{"A"})
		if !result.Valid {
			t.Fatalf("use %d: expected valid, got %+v", i+1, result)
		}
	}

	// 4th use should fail (token auto-removed after 3rd)
	result := s.Use(tok.ID, []string{"A"})
	if result.Valid || result.Reason != "not_found" {
		t.Errorf("expected not_found after exhaustion, got %+v", result)
	}
}

func TestUseUnlimited(t *testing.T) {
	s := newTestStore(time.Now())

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60, MaxUses: 0})

	// Should succeed many times without exhausting
	for i := 0; i < 100; i++ {
		result := s.Use(tok.ID, []string{"A"})
		if !result.Valid {
			t.Fatalf("use %d: expected valid, got %+v", i+1, result)
		}
	}
}

func TestUseInvalidToken(t *testing.T) {
	s := newTestStore(time.Now())

	result := s.Use("nonexistent", []string{"A"})
	if result.Valid || result.Reason != "not_found" {
		t.Errorf("expected not_found, got %+v", result)
	}
}

func TestRevokeSuccess(t *testing.T) {
	s := newTestStore(time.Now())

	tok, _ := s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60})

	if !s.Revoke(tok.ID) {
		t.Error("expected Revoke to return true")
	}

	result := s.Validate(tok.ID, []string{"A"})
	if result.Valid {
		t.Error("expected token to be invalid after revoke")
	}
}

func TestRevokeNotFound(t *testing.T) {
	s := newTestStore(time.Now())

	if s.Revoke("nonexistent") {
		t.Error("expected Revoke to return false for nonexistent token")
	}
}

func TestListFiltersExpired(t *testing.T) {
	now := time.Now()
	s := newTestStore(now)

	_, _ = s.Mint(MintRequest{Secrets: []string{"A"}, TTLSecs: 60})
	_, _ = s.Mint(MintRequest{Secrets: []string{"B"}, TTLSecs: 10})

	// Advance past the short-lived token
	s.now = func() time.Time { return now.Add(15 * time.Second) }

	tokens := s.List()
	if len(tokens) != 1 {
		t.Fatalf("expected 1 active token, got %d", len(tokens))
	}
	if tokens[0].Secrets[0] != "A" {
		t.Errorf("expected secret A to survive, got %v", tokens[0].Secrets)
	}
}

func TestListEmpty(t *testing.T) {
	s := newTestStore(time.Now())

	tokens := s.List()
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens, got %d", len(tokens))
	}
}

func TestConcurrency(t *testing.T) {
	s := NewStore()

	var wg sync.WaitGroup
	errs := make(chan error, 300)

	// 100 goroutines minting
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Mint(MintRequest{Secrets: []string{"S"}, TTLSecs: 300, MaxUses: 10})
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent mint error: %v", err)
	}

	tokens := s.List()
	if len(tokens) != 100 {
		t.Fatalf("expected 100 tokens, got %d", len(tokens))
	}

	// Concurrent validate + use on all tokens
	var wg2 sync.WaitGroup
	for _, tok := range tokens {
		wg2.Add(2)
		go func(id string) {
			defer wg2.Done()
			s.Validate(id, []string{"S"})
		}(tok.ID)
		go func(id string) {
			defer wg2.Done()
			s.Use(id, []string{"S"})
		}(tok.ID)
	}
	wg2.Wait()
}

func TestContextHelpers(t *testing.T) {
	ctx := WithTokenID(t.Context(), "test-id")

	id, ok := TokenIDFromContext(ctx)
	if !ok || id != "test-id" {
		t.Errorf("expected test-id, got %q (ok=%v)", id, ok)
	}

	// Empty context should return false
	_, ok = TokenIDFromContext(t.Context())
	if ok {
		t.Error("expected ok=false for empty context")
	}

	// Empty string should return false
	ctx = WithTokenID(t.Context(), "")
	_, ok = TokenIDFromContext(ctx)
	if ok {
		t.Error("expected ok=false for empty token ID")
	}
}
