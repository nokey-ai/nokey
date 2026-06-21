package metadata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nokey-ai/nokey/internal/config"
)

type SecretMeta struct {
	CreatedAt    time.Time  `json:"created_at"`
	LastAccessed time.Time  `json:"last_accessed"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	SetCount     int        `json:"set_count"`
}

type Store struct {
	path string
	mu   sync.Mutex
	data map[string]*SecretMeta
}

var NowFn = func() time.Time { return time.Now().UTC() }

func NewStore(path string) *Store {
	return &Store{path: path, data: nil}
}

func DefaultStore() (*Store, error) {
	dir, err := config.ConfigDir()
	if err != nil {
		return nil, err
	}
	return NewStore(filepath.Join(dir, "secrets_meta.json")), nil
}

func (s *Store) load() error {
	if s.data != nil {
		return nil
	}
	s.data = make(map[string]*SecretMeta)

	f, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(f) == 0 {
		return nil
	}
	return json.Unmarshal(f, &s.data)
}

func (s *Store) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) RecordSet(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return err
	}

	now := NowFn()
	meta, exists := s.data[key]
	if !exists {
		meta = &SecretMeta{CreatedAt: now}
		s.data[key] = meta
	}
	meta.SetCount++
	meta.LastAccessed = now
	return s.save()
}

func (s *Store) RecordAccess(keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return err
	}

	now := NowFn()
	for _, key := range keys {
		meta, exists := s.data[key]
		if !exists {
			meta = &SecretMeta{CreatedAt: time.Time{}}
			s.data[key] = meta
		}
		meta.LastAccessed = now
	}
	return s.save()
}

func (s *Store) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return err
	}

	delete(s.data, key)
	return s.save()
}

func (s *Store) GetMeta(key string) (*SecretMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return nil, err
	}

	meta, exists := s.data[key]
	if !exists {
		return nil, nil
	}
	cp := *meta
	return &cp, nil
}

func (s *Store) ListStale(maxIdle time.Duration) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return nil, err
	}

	now := NowFn()
	cutoff := now.Add(-maxIdle)
	var stale []string
	for key, meta := range s.data {
		if !meta.LastAccessed.IsZero() && meta.LastAccessed.Before(cutoff) {
			stale = append(stale, key)
		}
	}
	return stale, nil
}

func (s *Store) ListExpired() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return nil, err
	}

	now := NowFn()
	var expired []string
	for key, meta := range s.data {
		if meta.ExpiresAt != nil && meta.ExpiresAt.Before(now) {
			expired = append(expired, key)
		}
	}
	return expired, nil
}

func (s *Store) All() (map[string]*SecretMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.load(); err != nil {
		return nil, err
	}

	cp := make(map[string]*SecretMeta, len(s.data))
	for k, v := range s.data {
		entry := *v
		cp[k] = &entry
	}
	return cp, nil
}
