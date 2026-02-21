package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	useStdin bool
)

var setCmd = &cobra.Command{
	Use:   "set KEY",
	Short: "Store a secret",
	Long: `Store a secret in the OS keyring.

By default, you will be prompted to enter the secret value securely.
Use --stdin to read the value from stdin instead (useful for piping).

Examples:
  nokey set OPENAI_API_KEY
  echo "sk-..." | nokey set OPENAI_API_KEY --stdin`,
	Args: cobra.ExactArgs(1),
	RunE: runSet,
}

func init() {
	rootCmd.AddCommand(setCmd)
	setCmd.Flags().BoolVar(&useStdin, "stdin", false, "Read secret value from stdin")
}

func runSet(cmd *cobra.Command, args []string) error {
	key := args[0]

	var value string
	var err error

	if useStdin {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			value = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	} else {
		// Prompt for value securely (no echo)
		fmt.Fprintf(os.Stderr, "Enter value for %s: ", key)

		// Check if stdin is a terminal
		if term.IsTerminal(int(os.Stdin.Fd())) {
			// Read password without echoing
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return fmt.Errorf("failed to read password: %w", err)
			}
			value = string(password)
			fmt.Fprintln(os.Stderr) // Print newline after password input
		} else {
			// Not a terminal, read normally
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				value = scanner.Text()
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read value: %w", err)
			}
		}
	}

	// Trim whitespace
	value = strings.TrimSpace(value)

	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	// Store the secret
	store, err := getKeyring()
	if err != nil {
		return err
	}

	err = store.Set(key, value)

	// Record audit entry if audit logging is enabled
	if cfg.Audit.Enabled {
		entry := audit.NewAuditEntry(
			"set",
			key,
			"none", // set operation doesn't require auth
			[]string{key},
			err == nil,
			"",
		)
		if err != nil {
			entry.ErrorMessage = err.Error()
		}

		// Record audit entry (ignore errors to not disrupt execution)
		if auditErr := audit.Record(store, entry); auditErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to record audit entry: %v\n", auditErr)
		}
	}

	if err != nil {
		return err
	}

	fmt.Printf("Secret '%s' stored successfully\n", key)
	return nil
}
