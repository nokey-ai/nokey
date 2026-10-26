//go:build darwin

package keyring

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gokeychain "github.com/byteness/go-keychain"
)

const (
	testKeychainPassword = "testpw"
	testService          = "nokey-test"
	otherBuild           = "cdhash:0123456789abcdef0123456789abcdef01234567"
)

// newPartitionedKeychain creates a throwaway keychain holding one item per
// account, written through byteness/keyring as nokey writes them, then
// replaces each item's partition list with partitions. Items written by
// /usr/bin/security get no partition list, so they can't be used here.
func newPartitionedKeychain(t *testing.T, partitions string, accounts ...string) string {
	t.Helper()
	if _, err := os.Stat("/usr/bin/security"); err != nil {
		t.Skip("/usr/bin/security not available")
	}
	// macOS only creates the modern keychain format, which has partition
	// lists, for a .keychain-db file inside a Library/Keychains directory.
	dir := filepath.Join(t.TempDir(), "Library", "Keychains")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "buildtrust.keychain-db")
	security := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("/usr/bin/security", args...).CombinedOutput(); err != nil {
			t.Skipf("security %s: %v (%s)", args[0], err, strings.TrimSpace(string(out)))
		}
	}
	security("create-keychain", "-p", testKeychainPassword, path)
	t.Cleanup(func() { _ = exec.Command("/usr/bin/security", "delete-keychain", path).Run() })
	security("unlock-keychain", "-p", testKeychainPassword, path)
	kc := gokeychain.NewWithPath(path)
	for _, acct := range accounts {
		// The same item byteness/keyring writes for nokey: trusting the
		// creating application gives it a partition list of the creator.
		item := gokeychain.NewItem()
		item.SetSecClass(gokeychain.SecClassGenericPassword)
		item.SetService(testService)
		item.SetAccount(acct)
		item.SetData([]byte("value-" + acct))
		item.UseKeychain(kc)
		item.SetAccess(&gokeychain.Access{Label: acct})
		if err := gokeychain.AddItem(item); err != nil {
			t.Fatalf("add %s: %v", acct, err)
		}
		security("set-generic-password-partition-list", "-S", partitions, "-k", testKeychainPassword, "-s", testService, "-a", acct, path)
	}
	return path
}

func testPassphrase(string) ([]byte, error) { return []byte(testKeychainPassword), nil }

func TestRunningBuildPartition(t *testing.T) {
	partition, _, err := runningBuildPartition()
	if err != nil {
		t.Skipf("test binary has no code signature: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/codesign", "-dvvv", exe).CombinedOutput()
	if err != nil {
		t.Skipf("codesign: %v", err)
	}
	var want string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "CDHash="); ok {
			want = "cdhash:" + v
		}
	}
	if partition != want {
		t.Errorf("runningBuildPartition() = %q, want %q from codesign", partition, want)
	}
}

func TestTrustBuild_LetsRunningBuildRead(t *testing.T) {
	self, _, err := runningBuildPartition()
	if err != nil {
		t.Skipf("test binary has no code signature: %v", err)
	}
	path := newPartitionedKeychain(t, "apple-tool:,"+otherBuild, "A", "B")

	if err := readWithoutPrompt(path, testService, "A"); err == nil {
		t.Fatal("read succeeded before trusting this build; the partition list isn't being enforced, so this test proves nothing")
	}

	n, err := trustBuild(path, testService, []string{"A", "B"}, self, testPassphrase)
	if err != nil {
		t.Fatalf("trustBuild: %v", err)
	}
	if n != 2 {
		t.Errorf("trustBuild updated %d items, want 2", n)
	}
	for _, acct := range []string{"A", "B"} {
		if err := readWithoutPrompt(path, testService, acct); err != nil {
			t.Errorf("read %s after trusting this build: %v", acct, err)
		}
		missing, err := partitionMissing(path, testService, acct, otherBuild)
		if err != nil {
			t.Fatal(err)
		}
		if missing {
			t.Errorf("%s lost its existing partition %s", acct, otherBuild)
		}
	}

	n, err = trustBuild(path, testService, []string{"A", "B"}, self, func(string) ([]byte, error) {
		t.Error("passphrase fetched although every item already trusts this build")
		return nil, errors.New("unexpected")
	})
	if err != nil || n != 0 {
		t.Errorf("second trustBuild = %d, %v; want 0, nil", n, err)
	}
}

func TestTrustBuild_WrongPasswordFails(t *testing.T) {
	path := newPartitionedKeychain(t, otherBuild, "A")
	_, err := trustBuild(path, testService, []string{"A"}, "cdhash:ffffffffffffffffffffffffffffffffffffffff", func(string) ([]byte, error) {
		return []byte("wrong"), nil
	})
	if err == nil {
		t.Fatal("trustBuild succeeded with the wrong keychain password")
	}
}

func TestTrustBuild_NoPassphraseLeavesItems(t *testing.T) {
	path := newPartitionedKeychain(t, otherBuild, "A")
	n, err := trustBuild(path, testService, []string{"A"}, "cdhash:ffffffffffffffffffffffffffffffffffffffff", func(string) ([]byte, error) {
		return nil, errors.New("no Touch ID item")
	})
	if err != nil || n != 0 {
		t.Errorf("trustBuild = %d, %v; want 0, nil", n, err)
	}
}
