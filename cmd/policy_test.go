package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/spf13/cobra"
)

const echoPolicy = "approval: never\nrules:\n  - commands: [\"echo\"]\n    secrets: [\"MY_KEY\"]\n"

// setupPolicyExec installs a test keyring holding MY_KEY and a config
// directory holding echoPolicy, approved.
func setupPolicyExec(t *testing.T) (string, func() (bool, error)) {
	t.Helper()
	store, _ := newTestStore()
	withTestKeyring(t, store)
	c := config.DefaultConfig()
	c.Audit.Enabled = false
	withTestConfig(t, c)
	dir := withTestConfigDir(t, echoPolicy)
	_ = store.Set("MY_KEY", "v")

	run := func() (bool, error) {
		withExecGlobals(t)
		osExitFn = func(int) {}
		ran := false
		execRunFn = func(string, []string, map[string]string, ...string) (int, error) {
			ran = true
			return 0, nil
		}
		skipConfirm = true
		authMethod = ""
		cmd := &cobra.Command{}
		cmd.Flags().BoolVar(&enableRedact, "redact", false, "")
		err := runExec(cmd, []string{"echo"})
		return ran, err
	}
	return dir, run
}

// An agent that rewrites policies.yaml can't change what nokey applies.
func TestRunExec_UnapprovedPolicyRefused(t *testing.T) {
	dir, run := setupPolicyExec(t)
	if ran, err := run(); err != nil || !ran {
		t.Fatalf("approved policy: ran = %v, err = %v", ran, err)
	}

	edited := echoPolicy + "  - commands: [\"*\"]\n    secrets: [\"*\"]\n"
	if err := os.WriteFile(policy.Path(dir), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	ran, err := run()
	if ran || err == nil || !strings.Contains(err.Error(), "nokey policy approve") {
		t.Fatalf("edited policy: ran = %v, err = %v; want a refusal naming 'nokey policy approve'", ran, err)
	}

	withPresence(t, nil)
	if err := runPolicyApprove(nil, nil); err != nil {
		t.Fatalf("runPolicyApprove: %v", err)
	}
	if ran, err := run(); err != nil || !ran {
		t.Errorf("after approval: ran = %v, err = %v", ran, err)
	}
}

// Deleting an approved policies.yaml doesn't lift its rules.
func TestRunExec_RemovedApprovedPolicyRefused(t *testing.T) {
	dir, run := setupPolicyExec(t)
	if err := os.Remove(policy.Path(dir)); err != nil {
		t.Fatal(err)
	}
	if ran, err := run(); ran || err == nil || !strings.Contains(err.Error(), "removed after it was approved") {
		t.Fatalf("ran = %v, err = %v; want a refusal", ran, err)
	}

	withPresence(t, nil)
	if err := runPolicyApprove(nil, nil); err != nil {
		t.Fatalf("runPolicyApprove: %v", err)
	}
	store, _ := getKeyring()
	if digest, _ := approvedPolicyDigest(store); digest != "" {
		t.Errorf("digest = %q after approving no policy, want none", digest)
	}
	if ran, err := run(); err != nil || !ran {
		t.Errorf("with no policy approved: ran = %v, err = %v", ran, err)
	}
}

func TestRunPolicyApprove_Declined(t *testing.T) {
	dir, _ := setupPolicyExec(t)
	store, _ := getKeyring()
	before, _ := approvedPolicyDigest(store)
	if err := os.WriteFile(policy.Path(dir), []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	withPresence(t, errors.New("not confirmed: cancelled"))
	if err := runPolicyApprove(nil, nil); err == nil {
		t.Fatal("approval went through without the person at the machine")
	}
	if after, _ := approvedPolicyDigest(store); after != before {
		t.Errorf("digest changed from %q to %q", before, after)
	}
}

// A typo is refused at approval, where the user is looking, instead of
// being ignored at runtime.
func TestRunPolicyApprove_RejectsUnknownKeys(t *testing.T) {
	dir, _ := setupPolicyExec(t)
	if err := os.WriteFile(policy.Path(dir), []byte("rules:\n  - commands: [\"echo\"]\n    secrets: [\"MY_KEY\"]\n    prompt: never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reasons := withPresence(t, nil)
	if err := runPolicyApprove(nil, nil); err == nil {
		t.Fatal("approved a policy with an unknown key")
	}
	if len(*reasons) != 0 {
		t.Errorf("asked for presence before validating: %q", *reasons)
	}
}
