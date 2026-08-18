package auth

import (
	"strings"
	"testing"
	"time"
)

// memStore is a minimal in-memory backoffStore for testing.
type memStore struct {
	data map[string]string
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]string)}
}

func (m *memStore) Get(key string) (string, error) {
	v, ok := m.data[key]
	if !ok {
		return "", &notFoundErr{key}
	}
	return v, nil
}

func (m *memStore) Set(key, value string) error {
	m.data[key] = value
	return nil
}

func (m *memStore) Delete(key string) error {
	delete(m.data, key)
	return nil
}

type notFoundErr struct{ key string }

func (e *notFoundErr) Error() string { return "not found: " + e.key }

func TestCheckBackoff_NoRecord(t *testing.T) {
	store := newMemStore()
	if err := checkBackoff(store); err != nil {
		t.Fatalf("expected no error with no record, got: %v", err)
	}
}

func TestCheckBackoff_BelowThreshold(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return now }

	// 2 failures — below threshold of 3
	recordFailure(store)
	recordFailure(store)

	if err := checkBackoff(store); err != nil {
		t.Fatalf("expected no backoff below threshold, got: %v", err)
	}
}

func TestCheckBackoff_AtThreshold_TooSoon(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		recordFailure(store)
	}

	// Immediately after 3rd failure — should be blocked (delay = 2^0 = 1s)
	err := checkBackoff(store)
	if err == nil {
		t.Fatal("expected backoff error after 3 failures")
	}
	if !strings.Contains(err.Error(), "too many failed attempts") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckBackoff_AtThreshold_AfterDelay(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		recordFailure(store)
	}

	// Advance past the 1-second delay
	nowFn = func() time.Time { return now.Add(2 * time.Second) }

	if err := checkBackoff(store); err != nil {
		t.Fatalf("expected no error after delay, got: %v", err)
	}
}

func TestCheckBackoff_ExponentialDelay(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return now }

	// 5 failures: delay = 2^(5-3) = 4 seconds
	for i := 0; i < 5; i++ {
		recordFailure(store)
	}

	// 3 seconds later — still blocked
	nowFn = func() time.Time { return now.Add(3 * time.Second) }
	if err := checkBackoff(store); err == nil {
		t.Fatal("expected backoff error at 3s with 4s delay")
	}

	// 5 seconds later — allowed
	nowFn = func() time.Time { return now.Add(5 * time.Second) }
	if err := checkBackoff(store); err != nil {
		t.Fatalf("expected no error after delay, got: %v", err)
	}
}

func TestCheckBackoff_MaxDelay(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return now }

	// 20 failures: 2^(20-3) = 131072, capped at 60s
	for i := 0; i < 20; i++ {
		recordFailure(store)
	}

	// 59 seconds — still blocked
	nowFn = func() time.Time { return now.Add(59 * time.Second) }
	if err := checkBackoff(store); err == nil {
		t.Fatal("expected backoff at 59s with 60s max delay")
	}

	// 61 seconds — allowed
	nowFn = func() time.Time { return now.Add(61 * time.Second) }
	if err := checkBackoff(store); err != nil {
		t.Fatalf("expected no error after max delay, got: %v", err)
	}
}

// registerStore installs store as the process-wide backoff store and restores
// the previous registration afterwards, so package tests stay isolated.
func registerStore(t *testing.T, store BackoffStore) {
	t.Helper()
	old := backoffStore()
	t.Cleanup(func() { SetBackoffStore(old) })
	SetBackoffStore(store)
}

// freezeClock pins nowFn so backoff delays are deterministic.
func freezeClock(t *testing.T) (now time.Time, advance func(time.Duration)) {
	t.Helper()
	old := nowFn
	t.Cleanup(func() { nowFn = old })

	now = time.Now().UTC()
	current := now
	nowFn = func() time.Time { return current }
	return now, func(d time.Duration) { current = now.Add(d) }
}

func TestSetBackoffStore_RoundTrip(t *testing.T) {
	store := newMemStore()
	registerStore(t, store)

	if got := backoffStore(); got != BackoffStore(store) {
		t.Fatalf("backoffStore() = %v, want the registered store", got)
	}

	SetBackoffStore(nil)
	if got := backoffStore(); got != nil {
		t.Fatalf("backoffStore() = %v, want nil after deregistering", got)
	}
}

// TestAuthenticate_RateLimitsAfterThreshold is the regression test for the
// backoff store never being wired: before registration existed, an unlimited
// number of wrong PINs was accepted at full speed.
func TestAuthenticate_RateLimitsAfterThreshold(t *testing.T) {
	store := newMemStore()
	registerStore(t, store)
	freezeClock(t)

	hash, err := HashPINArgon2id("correctpin")
	if err != nil {
		t.Fatalf("HashPINArgon2id: %v", err)
	}

	wrong := [][]byte{[]byte("wrong1"), []byte("wrong2"), []byte("wrong3")}
	stubTerminal(t, true, wrong...)

	for i := range wrong {
		err := Authenticate(hash)
		if err == nil {
			t.Fatalf("attempt %d: expected failure", i+1)
		}
		if !strings.Contains(err.Error(), "incorrect PIN") {
			t.Fatalf("attempt %d: got %v, want incorrect PIN", i+1, err)
		}
	}

	// Fourth attempt is refused before the PIN is even read — stubTerminal has
	// no passwords left, so reaching the prompt would surface a different error.
	err = Authenticate(hash)
	if err == nil {
		t.Fatal("expected backoff error after 3 failed attempts")
	}
	if !strings.Contains(err.Error(), "too many failed attempts") {
		t.Fatalf("got %v, want backoff error", err)
	}
}

func TestAuthenticate_SuccessClearsFailures(t *testing.T) {
	store := newMemStore()
	registerStore(t, store)
	_, advance := freezeClock(t)

	pin := "correctpin"
	hash, err := HashPINArgon2id(pin)
	if err != nil {
		t.Fatalf("HashPINArgon2id: %v", err)
	}

	stubTerminal(t, true, []byte("wrong1"), []byte("wrong2"), []byte(pin))

	for i := 0; i < 2; i++ {
		if err := Authenticate(hash); err == nil {
			t.Fatalf("attempt %d: expected failure", i+1)
		}
	}

	// Below the threshold, so the correct PIN is still accepted.
	if err := Authenticate(hash); err != nil {
		t.Fatalf("correct PIN should authenticate: %v", err)
	}

	if _, ok := store.data[failureKey]; ok {
		t.Error("failure record should be cleared after successful auth")
	}

	// A later attempt is not penalised by the earlier failures.
	advance(time.Hour)
	stubTerminal(t, true, []byte(pin))
	if err := Authenticate(hash); err != nil {
		t.Fatalf("authentication after cleared failures: %v", err)
	}
}

// TestAuthenticate_FailuresPersistAcrossProcesses simulates a fresh nokey
// process: a new Store instance over the same backing data must still see the
// failure record, otherwise the limiter could be reset by re-running the CLI.
func TestAuthenticate_FailuresPersistAcrossProcesses(t *testing.T) {
	shared := newMemStore()
	registerStore(t, shared)
	freezeClock(t)

	hash, err := HashPINArgon2id("correctpin")
	if err != nil {
		t.Fatalf("HashPINArgon2id: %v", err)
	}

	stubTerminal(t, true, []byte("w1"), []byte("w2"), []byte("w3"))
	for i := 0; i < 3; i++ {
		if err := Authenticate(hash); err == nil {
			t.Fatalf("attempt %d: expected failure", i+1)
		}
	}

	// New store instance, same persisted data — as a second CLI invocation sees it.
	reopened := &memStore{data: shared.data}
	registerStore(t, reopened)

	err = Authenticate(hash)
	if err == nil || !strings.Contains(err.Error(), "too many failed attempts") {
		t.Fatalf("got %v, want backoff to survive a store reopen", err)
	}
}

func TestClearFailures_ResetsBackoff(t *testing.T) {
	store := newMemStore()
	now := time.Now().UTC()
	old := nowFn
	defer func() { nowFn = old }()
	nowFn = func() time.Time { return now }

	for i := 0; i < 5; i++ {
		recordFailure(store)
	}

	clearFailures(store)

	// Should be allowed immediately
	if err := checkBackoff(store); err != nil {
		t.Fatalf("expected no error after clear, got: %v", err)
	}
}
