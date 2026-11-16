package cmd

import (
	"fmt"
	"os"

	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Approve changes to policies.yaml",
	Long: `policies.yaml is a file any program running as you can edit, so nokey
only applies a version you have approved. After editing it, run
'nokey policy approve' in a terminal.`,
}

var policyApproveCmd = &cobra.Command{
	Use:   "approve",
	Short: "Approve policies.yaml as it is now",
	Long: `Show policies.yaml, ask you to confirm with Touch ID, the login password or
your PIN, and record its SHA-256 in the keyring. nokey exec, the proxy and the
MCP server then apply it. A later edit is not applied until you approve again.

If policies.yaml has been removed, this approves running without one.`,
	Args: cobra.NoArgs,
	RunE: runPolicyApprove,
}

func init() {
	rootCmd.AddCommand(policyCmd)
	policyCmd.AddCommand(policyApproveCmd)
}

func runPolicyApprove(cmd *cobra.Command, _ []string) error {
	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}
	return approvePolicy(cmd, store, configDir)
}

// approvePolicy asks the person at the machine to approve policies.yaml as
// it is now and stores its digest, or clears the digest if the file is gone.
func approvePolicy(cmd *cobra.Command, store *keyring.Store, configDir string) error {
	path := policy.Path(configDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		current, err := approvedPolicyDigest(store)
		if err != nil {
			return err
		}
		if current == "" {
			fmt.Printf("No %s and none approved: nothing to approve.\n", path)
			return nil
		}
		if err := confirmHuman(cmdContext(cmd), store, "approve running with no policies.yaml", false); err != nil {
			return err
		}
		if err := store.DeleteInternal(policy.DigestKey); err != nil && !keyring.IsNotFound(err) {
			return err
		}
		AppFromCmd(cmd).RecordAudit(store, "policy:approve", path, "presence", nil, true, "no policy")
		fmt.Printf("Approved running without %s.\n", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}
	// Approve only a file that loads, and catch typos here, where the user
	// is looking, rather than have the policy silently mean something else.
	// The bytes checked are the ones shown and digested.
	if _, err := policy.ParseStrict(data); err != nil {
		return err
	}

	digest := policy.Digest(data)
	if current, err := approvedPolicyDigest(store); err != nil {
		return err
	} else if current == digest {
		fmt.Printf("%s is already approved.\n", path)
		return nil
	}

	fmt.Fprintf(os.Stderr, "--- %s ---\n%s", path, data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintf(os.Stderr, "--- sha256 %s ---\n", digest)
	if err := confirmHuman(cmdContext(cmd), store, fmt.Sprintf("approve policies.yaml (sha256 %.12s)", digest), false); err != nil {
		return err
	}
	if err := store.SetInternal(policy.DigestKey, digest); err != nil {
		return err
	}
	AppFromCmd(cmd).RecordAudit(store, "policy:approve", path, "presence", nil, true, digest)
	fmt.Printf("Approved %s.\n", path)
	return nil
}

// approvedPolicyDigest returns the digest `nokey policy approve` stored,
// or "" if none is.
func approvedPolicyDigest(store *keyring.Store) (string, error) {
	digest, err := store.GetInternal(policy.DigestKey)
	if keyring.IsNotFound(err) {
		return "", nil
	}
	return digest, err
}

// loadApprovedPolicy loads policies.yaml if the user approved it as it is.
func loadApprovedPolicy(store *keyring.Store, configDir string) (*policy.Policy, error) {
	digest, err := approvedPolicyDigest(store)
	if err != nil {
		return nil, fmt.Errorf("failed to read the approved policy digest: %w", err)
	}
	return policy.LoadApproved(configDir, digest)
}

// policyApproved reports whether policies.yaml in configDir, which exists,
// is the approved version.
func policyApproved(store *keyring.Store, configDir string) bool {
	_, err := loadApprovedPolicy(store, configDir)
	return err == nil
}
