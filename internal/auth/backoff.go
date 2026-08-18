package auth

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	failureKey       = "__nokey_auth_failures__"
	backoffThreshold = 3
	maxDelaySecs     = 60
)

// FailureRecord tracks consecutive authentication failures.
type FailureRecord struct {
	Count       int       `json:"count"`
	LastFailure time.Time `json:"last_failure"`
}

// BackoffStore persists the failure counter across processes. It is satisfied
// by *keyring.Store, which this package cannot reference directly because
// internal/keyring imports internal/auth.
type BackoffStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

var (
	backoffMu       sync.RWMutex
	registeredStore BackoffStore
)

// SetBackoffStore registers the store used to rate-limit failed PIN attempts.
// internal/keyring calls this when a Store is opened, so any process that can
// reach a PIN hash also has somewhere to persist failures. Passing nil disables
// rate limiting.
func SetBackoffStore(store BackoffStore) {
	backoffMu.Lock()
	defer backoffMu.Unlock()
	registeredStore = store
}

// backoffStore returns the registered store, or nil if none was registered.
func backoffStore() BackoffStore {
	backoffMu.RLock()
	defer backoffMu.RUnlock()
	return registeredStore
}

// checkBackoff returns an error if the caller must wait before another attempt.
func checkBackoff(store BackoffStore) error {
	rec, err := loadFailureRecord(store)
	if err != nil || rec == nil {
		return nil // no record or error reading — allow attempt
	}

	if rec.Count < backoffThreshold {
		return nil
	}

	delaySecs := math.Min(math.Pow(2, float64(rec.Count-backoffThreshold)), maxDelaySecs)
	earliest := rec.LastFailure.Add(time.Duration(delaySecs) * time.Second)

	if nowFn().Before(earliest) {
		remaining := earliest.Sub(nowFn()).Round(time.Second)
		return fmt.Errorf("too many failed attempts — try again in %s", remaining)
	}

	return nil
}

// recordFailure increments the failure counter.
func recordFailure(store BackoffStore) {
	rec, err := loadFailureRecord(store)
	if err != nil || rec == nil {
		rec = &FailureRecord{}
	}
	rec.Count++
	rec.LastFailure = nowFn()
	saveFailureRecord(store, rec)
}

// clearFailures resets the counter on successful auth.
func clearFailures(store BackoffStore) {
	_ = store.Delete(failureKey)
}

func loadFailureRecord(store BackoffStore) (*FailureRecord, error) {
	data, err := store.Get(failureKey)
	if err != nil {
		return nil, err
	}
	var rec FailureRecord
	if err := json.Unmarshal([]byte(data), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func saveFailureRecord(store BackoffStore, rec *FailureRecord) {
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = store.Set(failureKey, string(data))
}

// nowFn is the clock used by backoff, overridable for testing.
var nowFn = func() time.Time { return time.Now().UTC() }
