package policy

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds the currently applied Policy for a long-running process (the
// MCP daemon) and picks up policies.yaml edits without a restart, but only
// edits the user has approved: a file whose digest doesn't match the one
// `nokey policy approve` stored is never applied, and the Store keeps the
// policy it already has. A process running as the user can rewrite the
// file, but not the approved digest.
//
// A Store is safe for concurrent use. Get is lock-free. Current and
// MaybeReload serialize on a mutex so concurrent reload attempts do not
// double-parse, but the atomic.Pointer swap is always visible to readers.
type Store struct {
	configDir string
	// approved returns the approved digest, "" if none. It must read the
	// keyring afresh: the user approves from another process.
	approved func() (string, error)
	current  atomic.Pointer[Policy]

	mu       sync.Mutex // guards lastMod, lastSize, exists, pending and reload sequencing
	lastMod  time.Time
	lastSize int64
	exists   bool
	// pending is set while the file on disk is not approved, so each call
	// checks again whether the user has approved it since.
	pending bool
}

// NewStore constructs a Store for configDir/policies.yaml and performs an
// initial load. approved returns the digest stored under DigestKey. An
// unapproved file is not an error: the Store starts with a nil Policy and
// warns on stderr. Returns an error if the approved digest can't be read,
// or the approved file is malformed.
func NewStore(configDir string, approved func() (string, error)) (*Store, error) {
	s := &Store{configDir: configDir, approved: approved}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		var na *NotApprovedError
		if !errors.As(err, &na) {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "Warning: %v. Until then no policy is applied, so every secret access asks for approval.\n", err)
	}
	return s, nil
}

// Get returns the most recently applied Policy without touching the
// filesystem. Lock-free; safe for concurrent use. May return nil.
func (s *Store) Get() *Policy {
	return s.current.Load()
}

// Current reloads policies.yaml if it changed, or if it was waiting for
// approval, and returns the applied Policy. A reload that fails (a
// malformed or unapproved file) is logged to stderr and keeps the
// previous Policy. Safe for concurrent use.
//
// This is the primary entry point for long-running daemons — it bundles the
// reload check with the read so callers cannot forget to refresh.
func (s *Store) Current() *Policy {
	if err := s.MaybeReload(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: policy not reloaded: %v\n", err)
	}
	return s.Get()
}

// MaybeReload stats policies.yaml and reloads it if its mtime, size or
// existence changed, or if the file on disk was waiting for approval.
// Returns nil if nothing changed or the reload succeeded. On error the
// applied Policy is kept; an unapproved file is reported only when it
// first appears, not on every call while it waits.
//
// Most callers should use Current instead. MaybeReload is exposed for tests
// and for advanced callers that need to separate the reload check from the
// policy read.
func (s *Store) MaybeReload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Stat(Path(s.configDir))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat policy file: %w", err)
	}
	exists := err == nil
	changed := exists != s.exists || (exists && (!info.ModTime().Equal(s.lastMod) || info.Size() != s.lastSize))
	if !changed && !s.pending {
		return nil
	}
	wasPending := s.pending && !changed

	err = s.load()
	var na *NotApprovedError
	if errors.As(err, &na) && wasPending {
		return nil // already reported
	}
	return err
}

// load reads the file and the approved digest and applies the policy if it
// is approved. Callers hold s.mu.
func (s *Store) load() error {
	// Record the file's state first, so a malformed or unapproved file is
	// reported once, not on every request, until it changes again.
	if info, err := os.Stat(Path(s.configDir)); err == nil {
		s.exists, s.lastMod, s.lastSize = true, info.ModTime(), info.Size()
	} else {
		s.exists, s.lastMod, s.lastSize = false, time.Time{}, 0
	}

	digest, err := s.approved()
	if err != nil {
		return fmt.Errorf("failed to read the approved policy digest: %w", err)
	}
	pol, err := LoadApproved(s.configDir, digest)
	var na *NotApprovedError
	s.pending = errors.As(err, &na)
	if err != nil {
		return err
	}
	s.current.Store(pol)
	return nil
}
