package auth

import (
	"encoding/json"
	"fmt"
	"math"
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

// backoffStoreFn abstracts keyring access for testing.
var backoffStoreFn = defaultBackoffStore

type backoffStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

func defaultBackoffStore() backoffStore {
	return nil // callers pass the store directly
}

// checkBackoff returns an error if the caller must wait before another attempt.
func checkBackoff(store backoffStore) error {
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
func recordFailure(store backoffStore) {
	rec, err := loadFailureRecord(store)
	if err != nil || rec == nil {
		rec = &FailureRecord{}
	}
	rec.Count++
	rec.LastFailure = nowFn()
	saveFailureRecord(store, rec)
}

// clearFailures resets the counter on successful auth.
func clearFailures(store backoffStore) {
	_ = store.Delete(failureKey)
}

func loadFailureRecord(store backoffStore) (*FailureRecord, error) {
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

func saveFailureRecord(store backoffStore, rec *FailureRecord) {
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = store.Set(failureKey, string(data))
}

// nowFn is the clock used by backoff, overridable for testing.
var nowFn = func() time.Time { return time.Now().UTC() }
