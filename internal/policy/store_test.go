package policy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// writePolicy writes policies.yaml into dir with the given content and
// optionally bumps its mtime by delta so mtime-change detection fires
// reliably even on filesystems with coarse timestamps.
func writePolicy(t *testing.T, dir, content string, bumpMtime time.Duration) {
	t.Helper()
	path := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if bumpMtime != 0 {
		mod := time.Now().Add(bumpMtime)
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
}

func TestNewStore_ValidFile(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`, 0)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	pol := s.Get()
	if pol == nil {
		t.Fatal("Get returned nil, want loaded policy")
	}
	if len(pol.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(pol.Rules))
	}
}

func TestNewStore_MissingFile(t *testing.T) {
	dir := t.TempDir()

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if pol := s.Get(); pol != nil {
		t.Errorf("Get = %v, want nil (allow-all) for missing file", pol)
	}
}

func TestNewStore_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules: [invalid yaml`, 0)

	_, err := NewStore(dir)
	if err == nil {
		t.Fatal("NewStore should return error for malformed file")
	}
}

func TestStore_CurrentReloadsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`, 0)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	pol := s.Current()
	if pol == nil || len(pol.Rules) != 1 || pol.Rules[0].Commands[0] != "gh" {
		t.Fatalf("initial Current = %+v, want single rule for gh", pol)
	}

	// Rewrite the file with a different rule and bump mtime forward.
	writePolicy(t, dir, `rules:
  - commands: ["ssh"]
    secrets: ["SSH_KEY"]
  - commands: ["aws"]
    secrets: ["AWS_*"]
`, 2*time.Second)

	pol = s.Current()
	if pol == nil {
		t.Fatal("post-reload Current returned nil")
	}
	if len(pol.Rules) != 2 {
		t.Fatalf("got %d rules after reload, want 2", len(pol.Rules))
	}
	if pol.Rules[0].Commands[0] != "ssh" {
		t.Errorf("rule 0 command = %q, want ssh", pol.Rules[0].Commands[0])
	}
}

func TestStore_CurrentNoopWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`, 0)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// First Current locks in the mtime/size.
	first := s.Current()

	// Plant a sentinel directly via the atomic pointer. A no-op Current
	// call must not overwrite it (because the file is unchanged).
	sentinel := &Policy{Rules: []Rule{{Commands: []string{"sentinel"}, Secrets: []string{"X"}}}}
	s.current.Store(sentinel)

	got := s.Current()
	if got != sentinel {
		t.Errorf("Current returned %+v, want the sentinel (no reload should have happened)", got)
	}
	_ = first
}

func TestStore_CurrentPreservesPreviousOnParseError(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`, 0)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	prev := s.Current()
	if prev == nil {
		t.Fatal("initial Current returned nil")
	}

	// Overwrite with malformed YAML and bump mtime.
	writePolicy(t, dir, `rules: [invalid yaml`, 2*time.Second)

	// MaybeReload returns the parse error but Current swallows it (logs to
	// stderr). Either way, the previously loaded Policy must still be
	// returned.
	if err := s.MaybeReload(); err == nil {
		t.Error("MaybeReload should return error for malformed file")
	}

	got := s.Get()
	if got != prev {
		t.Errorf("Get = %+v, want previous policy %+v (unchanged on parse error)", got, prev)
	}
}

func TestStore_CurrentHandlesDeletion(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules:
  - commands: ["gh"]
    secrets: ["GITHUB_TOKEN"]
`, 0)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Current() == nil {
		t.Fatal("initial Current returned nil")
	}

	if err := os.Remove(filepath.Join(dir, "policies.yaml")); err != nil {
		t.Fatalf("remove: %v", err)
	}

	got := s.Current()
	if got != nil {
		t.Errorf("Current after deletion = %+v, want nil (allow-all)", got)
	}
}

func TestStore_CurrentHandlesLateCreation(t *testing.T) {
	dir := t.TempDir()

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Get() != nil {
		t.Fatal("initial Get with missing file should be nil")
	}

	writePolicy(t, dir, `rules:
  - commands: ["curl"]
    secrets: ["*"]
`, 0)

	pol := s.Current()
	if pol == nil {
		t.Fatal("Current after file creation returned nil")
	}
	if len(pol.Rules) != 1 || pol.Rules[0].Commands[0] != "curl" {
		t.Errorf("got %+v, want single rule for curl", pol)
	}
}

func TestStore_ConcurrentGetAndCurrent(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, `rules:
  - commands: ["cmd0"]
    secrets: ["*"]
`, 0)

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers hammer Get and Current.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.Get()
					_ = s.Current()
				}
			}
		}()
	}

	// Writer rewrites the file a few times, bumping mtime each time.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 10; i++ {
			content := "rules:\n  - commands: [\"cmd" + string(rune('0'+i%10)) + "\"]\n    secrets: [\"*\"]\n"
			writePolicy(t, dir, content, time.Duration(i)*time.Second)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Let the race run for a short while, then stop.
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Final Current should return the last-written content without error.
	pol := s.Current()
	if pol == nil {
		t.Fatal("final Current returned nil")
	}
}
