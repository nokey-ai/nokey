package audit

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/byteness/keyring"
	nokeyKeyring "github.com/nokey-ai/nokey/internal/keyring"
)

// Environment for TestAuditHelperProcess, which runs as a separate nokey
// process appending to a shared audit log.
const (
	helperDirEnv   = "NOKEY_AUDIT_HELPER_DIR"
	helperKeyEnv   = "NOKEY_AUDIT_HELPER_KEY"
	helperCountEnv = "NOKEY_AUDIT_HELPER_COUNT"
	helperMaxEnv   = "NOKEY_AUDIT_HELPER_MAX"
)

// TestAuditHelperProcess is not a real test. The cross-process tests below
// re-run the test binary with it selected, so each writer is its own process
// with its own recordMu, the way the CLI and the MCP server are.
func TestAuditHelperProcess(t *testing.T) {
	dir := os.Getenv(helperDirEnv)
	if dir == "" {
		t.Skip("helper process only")
	}
	count, _ := strconv.Atoi(os.Getenv(helperCountEnv))
	maxEntries, _ := strconv.Atoi(os.Getenv(helperMaxEnv))

	AuditLogDir = func() (string, error) { return dir, nil }
	store := newTestStore()
	if err := store.Set(AuditEncryptionKeyKey, os.Getenv(helperKeyEnv)); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	for i := 0; i < count; i++ {
		e := NewAuditEntry("exec", fmt.Sprintf("pid%d-%d", os.Getpid(), i), "pin", nil, true, "")
		if err := Record(store, e, maxEntries, 90); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
}

// runAuditWriters starts procs helper processes that each record perProc
// entries into dir, and waits for all of them.
func runAuditWriters(t *testing.T, dir, key string, procs, perProc, maxEntries int) {
	t.Helper()
	var wg sync.WaitGroup
	for p := 0; p < procs; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestAuditHelperProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(),
				helperDirEnv+"="+dir,
				helperKeyEnv+"="+key,
				helperCountEnv+"="+strconv.Itoa(perProc),
				helperMaxEnv+"="+strconv.Itoa(maxEntries),
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("writer process: %v\n%s", err, out)
			}
		}()
	}
	wg.Wait()
}

// sharedKey is a fixed audit encryption key, in its stored form, for the
// test and its helper processes to agree on.
func sharedKey() string {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(raw[:])
}

func assertIntactChain(t *testing.T, log *AuditLog) {
	t.Helper()
	for _, w := range log.Warnings {
		if strings.Contains(w, "chain break") || strings.Contains(w, "tampering") || strings.Contains(w, "truncation") {
			t.Errorf("unexpected integrity warning: %s", w)
		}
	}
}

// TestRecord_CrossProcessAppend is the multi-writer case recordMu cannot
// cover: separate processes read the same chain head and each appended an
// entry linked to it, forking the chain.
func TestRecord_CrossProcessAppend(t *testing.T) {
	dir := withTestAuditDir(t)
	key := sharedKey()
	store := newTestStore()
	if err := store.Set(AuditEncryptionKeyKey, key); err != nil {
		t.Fatal(err)
	}

	const procs, perProc = 6, 25
	runAuditWriters(t, dir, key, procs, perProc, 1000)

	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := procs * perProc; len(log.Entries) != want {
		t.Errorf("got %d entries, want %d", len(log.Entries), want)
	}
	assertIntactChain(t, log)

	if tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(tmps) > 0 {
		t.Errorf("temp files left behind: %v", tmps)
	}
}

// TestRecord_CrossProcessCompaction drives compaction while other processes
// append. A rename under a concurrent appender drops its entry or leaves the
// chain head describing a file that no longer exists.
func TestRecord_CrossProcessCompaction(t *testing.T) {
	dir := withTestAuditDir(t)
	key := sharedKey()
	store := newTestStore()
	if err := store.Set(AuditEncryptionKeyKey, key); err != nil {
		t.Fatal(err)
	}

	runAuditWriters(t, dir, key, 6, 25, 10)

	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertIntactChain(t, log)
}

// TestLoad_ReadOnlyDir checks Load still works where it cannot create the
// lock file, as it did before there was one: an audit dir on a read-only
// mount, or one owned by another user.
func TestLoad_ReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions enforced")
	}
	dir := withTestAuditDir(t)
	store := newTestStore()
	if err := Record(store, NewAuditEntry("exec", "ls", "pin", nil, true, ""), 1000, 90); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatalf("remove lock: %v", err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	log, err := Load(store)
	if err != nil {
		t.Fatalf("Load on a read-only dir: %v", err)
	}
	if len(log.Entries) != 1 {
		t.Errorf("got %d entries, want 1", len(log.Entries))
	}
}

// TestLoad_ReadOnlyLockFile checks an existing lock file that is not writable
// still serves as a lock: flock needs no write access.
func TestLoad_ReadOnlyLockFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions enforced")
	}
	dir := withTestAuditDir(t)
	store := newTestStore()
	if err := Record(store, NewAuditEntry("exec", "ls", "pin", nil, true, ""), 1000, 90); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, lockFileName), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(store); err != nil {
		t.Fatalf("Load with a read-only lock file: %v", err)
	}
}

// TestLoad_DoesNotCreateDir checks reading the log has no side effect on a
// machine that has never written one.
func TestLoad_DoesNotCreateDir(t *testing.T) {
	withTestAuditDir(t)
	dir := filepath.Join(t.TempDir(), "never-created")
	AuditLogDir = func() (string, error) { return dir, nil }

	log, err := Load(newTestStore())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(log.Entries) != 0 {
		t.Errorf("got %d entries, want 0", len(log.Entries))
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Load created the audit dir (stat err = %v)", err)
	}
}

// TestRecord_RemovesStaleChainHeadTemps checks temp files left by a writer
// that died between write and rename are cleared, including the fixed name
// older versions used.
func TestRecord_RemovesStaleChainHeadTemps(t *testing.T) {
	dir := withTestAuditDir(t)
	stale := []string{chainHeadFileName + ".tmp", chainHeadFileName + ".123456.tmp"}
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := Record(newTestStore(), NewAuditEntry("exec", "ls", "pin", nil, true, ""), 1000, 90); err != nil {
		t.Fatalf("Record: %v", err)
	}
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived Record (stat err = %v)", name, err)
		}
	}
}

// TestRecord_RemovesStaleChainHeadTemps_GlobCharsInPath checks the cleanup
// does not treat the config dir as a pattern: a path containing [, * or ?
// is a valid directory name, and a malformed pattern matched nothing.
func TestRecord_RemovesStaleChainHeadTemps_GlobCharsInPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("* and ? are not valid in Windows file names")
	}
	withTestAuditDir(t)
	dir := filepath.Join(t.TempDir(), "odd[dir*name?")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	AuditLogDir = func() (string, error) { return dir, nil }

	stale := filepath.Join(dir, chainHeadFileName+".123456.tmp")
	if err := os.WriteFile(stale, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Record(newTestStore(), NewAuditEntry("exec", "ls", "pin", nil, true, ""), 1000, 90); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp survived Record (stat err = %v)", err)
	}
}

// blockingRing holds Get of the audit key until released, standing in for a
// Keychain prompt the user has not answered yet.
type blockingRing struct {
	*mockRing
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingRing) Get(key string) (keyring.Item, error) {
	if key == AuditEncryptionKeyKey {
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return b.mockRing.Get(key)
}

// TestRecord_KeyPromptDoesNotHoldLock checks the audit lock is not held while
// the encryption key is fetched, so one process waiting on a Keychain prompt
// does not stall every other nokey process that wants to record.
func TestRecord_KeyPromptDoesNotHoldLock(t *testing.T) {
	withTestAuditDir(t)
	ring := &blockingRing{mockRing: newMockRing(), entered: make(chan struct{}), release: make(chan struct{})}
	if err := ring.Set(keyring.Item{Key: AuditEncryptionKeyKey, Data: []byte(sharedKey())}); err != nil {
		t.Fatal(err)
	}
	store := nokeyKeyring.NewWithRing(ring, "test")

	done := make(chan error, 1)
	go func() {
		done <- Record(store, NewAuditEntry("exec", "ls", "pin", nil, true, ""), 1000, 90)
	}()
	<-ring.entered

	acquired := make(chan func(), 1)
	go func() {
		unlock, err := lockAuditDir()
		if err != nil {
			t.Errorf("lockAuditDir: %v", err)
			unlock = func() {}
		}
		acquired <- unlock
	}()

	select {
	case unlock := <-acquired:
		unlock()
		close(ring.release)
	case <-time.After(2 * time.Second):
		close(ring.release)
		(<-acquired)()
		t.Error("audit lock held while waiting for the encryption key")
	}
	if err := <-done; err != nil {
		t.Errorf("Record: %v", err)
	}
}
