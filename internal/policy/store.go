package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds the currently loaded Policy and reloads it from policies.yaml
// when the underlying file changes on disk. It is intended for long-running
// processes (the MCP daemon) that must pick up policy edits without restart.
//
// A Store is safe for concurrent use. Get is lock-free. Current and
// MaybeReload serialize on a mutex so concurrent reload attempts do not
// double-parse, but the atomic.Pointer swap is always visible to readers.
type Store struct {
	configDir string
	current   atomic.Pointer[Policy]

	mu       sync.Mutex // guards lastMod, lastSize, and reload sequencing
	lastMod  time.Time
	lastSize int64
}

// NewStore constructs a Store for configDir/policies.yaml and performs an
// initial load. Returns an error only if the file exists but is malformed;
// a missing file yields a Store holding a nil Policy (allow-all, matching
// Load semantics).
func NewStore(configDir string) (*Store, error) {
	s := &Store{configDir: configDir}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Get returns the most recently loaded Policy without touching the
// filesystem. Lock-free; safe for concurrent use. May return nil (allow-all).
func (s *Store) Get() *Policy {
	return s.current.Load()
}

// Current stats policies.yaml, reloads if its mtime or size has changed since
// the last load, and returns the current Policy. On parse error it logs a
// warning to stderr and keeps the previously loaded Policy in place. Safe
// for concurrent use.
//
// This is the primary entry point for long-running daemons — it bundles the
// reload check with the read so callers cannot forget to refresh.
func (s *Store) Current() *Policy {
	if err := s.MaybeReload(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to reload policy: %v\n", err)
	}
	return s.Get()
}

// MaybeReload stats policies.yaml and reloads it if mtime or size has changed.
// Returns nil if the file is unchanged or the reload succeeds. Returns an
// error only when the file changed but the new contents are malformed; in
// that case the previously loaded Policy is preserved.
//
// Most callers should use Current instead. MaybeReload is exposed for tests
// and for advanced callers that need to separate the reload check from the
// policy read.
func (s *Store) MaybeReload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.configDir, "policies.yaml")
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File was removed since the last load: drop to nil policy
			// (allow-all), matching the "missing file" initial state.
			if s.current.Load() != nil || !s.lastMod.IsZero() || s.lastSize != 0 {
				s.current.Store(nil)
				s.lastMod = time.Time{}
				s.lastSize = 0
			}
			return nil
		}
		return fmt.Errorf("failed to stat policy file: %w", err)
	}

	if info.ModTime().Equal(s.lastMod) && info.Size() == s.lastSize {
		return nil // unchanged
	}

	// Record the new stat values before attempting the parse so that a
	// malformed file is logged once, not on every subsequent request, until
	// the file is edited again.
	s.lastMod = info.ModTime()
	s.lastSize = info.Size()

	pol, err := Load(s.configDir)
	if err != nil {
		return err
	}
	s.current.Store(pol)
	return nil
}

// reload performs an unconditional load and swap. Used by NewStore for the
// initial load.
func (s *Store) reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pol, err := Load(s.configDir)
	if err != nil {
		return err
	}
	s.current.Store(pol)

	// Record stat info so MaybeReload can detect subsequent changes. A
	// missing file is normal here and leaves lastMod/lastSize at zero.
	path := filepath.Join(s.configDir, "policies.yaml")
	if info, statErr := os.Stat(path); statErr == nil {
		s.lastMod = info.ModTime()
		s.lastSize = info.Size()
	}
	return nil
}
