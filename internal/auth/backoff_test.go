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
