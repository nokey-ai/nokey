package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/spf13/cobra"
)

var (
	auditSince     string
	auditSecret    string
	auditCommand   string
	auditOperation string
	auditLimit     int
	auditFormat    string
	auditOutput    string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Manage audit logs",
	Long: `View and export audit logs of secret access and operations.

Audit logs track when secrets are accessed, by whom, and with what authentication method.
All logs are encrypted and stored securely in your OS keyring.

Examples:
  nokey audit list
  nokey audit list --since 1d
  nokey audit list --secret API_KEY
  nokey audit export --format json --output audit.json`,
}

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit log entries",
	Long: `List audit log entries with optional filtering.

Time filters:
  --since 1h    Last hour
  --since 1d    Last day
  --since 1w    Last week
  --since 1m    Last month

Examples:
  nokey audit list
  nokey audit list --since 1d --limit 50
  nokey audit list --secret OPENAI_API_KEY
  nokey audit list --command claude
  nokey audit list --operation exec`,
	RunE: runAuditList,
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log to file",
	Long: `Export audit log entries to JSON or CSV format.

Examples:
  nokey audit export --format json
  nokey audit export --format csv --output audit.csv
  nokey audit export --format json --since 7d --output last-week.json`,
	RunE: runAuditExport,
}

var auditClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all audit log entries",
	Long:  `Clear all audit log entries. This requires authentication.`,
	RunE:  runAuditClear,
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditClearCmd)

	// List flags
	auditListCmd.Flags().StringVar(&auditSince, "since", "", "Show entries since time (1h, 1d, 1w, 1m)")
	auditListCmd.Flags().StringVar(&auditSecret, "secret", "", "Filter by secret name")
	auditListCmd.Flags().StringVar(&auditCommand, "command", "", "Filter by command")
	auditListCmd.Flags().StringVar(&auditOperation, "operation", "", "Filter by operation (exec, set, delete, import, auth)")
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum number of entries to show")

	// Export flags
	auditExportCmd.Flags().StringVar(&auditFormat, "format", "json", "Export format (json or csv)")
	auditExportCmd.Flags().StringVar(&auditOutput, "output", "", "Output file (default: stdout)")
	auditExportCmd.Flags().StringVar(&auditSince, "since", "", "Export entries since time (1h, 1d, 1w, 1m)")
	auditExportCmd.Flags().StringVar(&auditSecret, "secret", "", "Filter by secret name")
	auditExportCmd.Flags().StringVar(&auditCommand, "command", "", "Filter by command")
	auditExportCmd.Flags().StringVar(&auditOperation, "operation", "", "Filter by operation")
}

func runAuditList(cmd *cobra.Command, args []string) error {
	if !cfg.Audit.Enabled {
		fmt.Fprintln(os.Stderr, "Audit logging is not enabled")
		fmt.Fprintln(os.Stderr, "\nTo enable audit logging, add to ~/.config/nokey/config.yaml:")
		fmt.Fprintln(os.Stderr, "  audit:")
		fmt.Fprintln(os.Stderr, "    enabled: true")
		return nil
	}

	store, err := getKeyring()
	if err != nil {
		return err
	}

	log, err := audit.Load(store)
	if err != nil {
		return fmt.Errorf("failed to load audit log: %w", err)
	}

	// Parse filters
	opts := audit.FilterOptions{
		SecretName: auditSecret,
		Command:    auditCommand,
		Operation:  auditOperation,
		Limit:      auditLimit,
	}

	if auditSince != "" {
		since, err := parseSince(auditSince)
		if err != nil {
			return err
		}
		opts.Since = &since
	}

	// Filter entries
	entries := log.Filter(opts)

	if len(entries) == 0 {
		fmt.Println("No audit entries found")
		return nil
	}

	// Display entries
	fmt.Printf("Audit Entries (%d):\n\n", len(entries))
	for i, entry := range entries {
		printAuditEntry(&entry, i+1)
		if i < len(entries)-1 {
			fmt.Println()
		}
	}

	return nil
}

func runAuditExport(cmd *cobra.Command, args []string) error {
	if !cfg.Audit.Enabled {
		return fmt.Errorf("audit logging is not enabled")
	}

	store, err := getKeyring()
	if err != nil {
		return err
	}

	log, err := audit.Load(store)
	if err != nil {
		return fmt.Errorf("failed to load audit log: %w", err)
	}

	// Parse filters
	opts := audit.FilterOptions{
		SecretName: auditSecret,
		Command:    auditCommand,
		Operation:  auditOperation,
		Limit:      0, // No limit for export
	}

	if auditSince != "" {
		since, err := parseSince(auditSince)
		if err != nil {
			return err
		}
		opts.Since = &since
	}

	// Filter entries
	entries := log.Filter(opts)

	// Export
	var data []byte
	switch strings.ToLower(auditFormat) {
	case "json":
		data, err = log.ExportJSON(entries)
	case "csv":
		data, err = log.ExportCSV(entries)
	default:
		return fmt.Errorf("unsupported format: %s (use 'json' or 'csv')", auditFormat)
	}

	if err != nil {
		return fmt.Errorf("failed to export: %w", err)
	}

	// Write output
	if auditOutput == "" {
		// Write to stdout
		fmt.Println(string(data))
	} else {
		// Write to file
		if err := os.WriteFile(auditOutput, data, 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Exported %d entries to %s\n", len(entries), auditOutput)
	}

	return nil
}

func runAuditClear(cmd *cobra.Command, args []string) error {
	if !cfg.Audit.Enabled {
		return fmt.Errorf("audit logging is not enabled")
	}

	store, err := getKeyring()
	if err != nil {
		return err
	}

	// Require authentication to clear audit log
	if cfg.RequireAuth || store.HasPIN() {
		storedHash, err := store.GetPINHash()
		if err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr, "Clearing audit log requires authentication")
		if err := authenticatePIN(storedHash); err != nil {
			return err
		}
	}

	// Create empty log
	emptyLog := &audit.AuditLog{Entries: []audit.AuditEntry{}}
	if err := emptyLog.Save(store); err != nil {
		return fmt.Errorf("failed to clear audit log: %w", err)
	}

	fmt.Println("Audit log cleared successfully")
	return nil
}

// printAuditEntry formats and prints a single audit entry
func printAuditEntry(entry *audit.AuditEntry, index int) {
	status := "✓"
	if !entry.Success {
		status = "✗"
	}

	fmt.Printf("[%d] %s %s\n", index, status, entry.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    Operation: %s\n", entry.Operation)
	fmt.Printf("    Command:   %s\n", entry.Command)
	if len(entry.SecretNames) > 0 {
		fmt.Printf("    Secrets:   %s\n", strings.Join(entry.SecretNames, ", "))
	}
	fmt.Printf("    Auth:      %s\n", entry.AuthMethod)
	fmt.Printf("    User:      %s@%s (PID: %d)\n", entry.User, entry.Hostname, entry.PID)
	if entry.ErrorMessage != "" {
		fmt.Printf("    Error:     %s\n", entry.ErrorMessage)
	}
}

// parseSince parses a time duration string (1h, 1d, 1w, 1m) and returns the cutoff time
func parseSince(since string) (time.Time, error) {
	if len(since) < 2 {
		return time.Time{}, fmt.Errorf("invalid time format: %s (use: 1h, 1d, 1w, 1m)", since)
	}

	unit := since[len(since)-1:]
	valueStr := since[:len(since)-1]

	var value int
	if _, err := fmt.Sscanf(valueStr, "%d", &value); err != nil {
		return time.Time{}, fmt.Errorf("invalid time value: %s", since)
	}

	now := time.Now().UTC()
	switch unit {
	case "h":
		return now.Add(-time.Duration(value) * time.Hour), nil
	case "d":
		return now.AddDate(0, 0, -value), nil
	case "w":
		return now.AddDate(0, 0, -value*7), nil
	case "m":
		return now.AddDate(0, -value, 0), nil
	default:
		return time.Time{}, fmt.Errorf("invalid time unit: %s (use: h, d, w, m)", unit)
	}
}

// authenticatePIN prompts for PIN and verifies it
func authenticatePIN(storedHash string) error {
	// Import auth package inline to avoid circular dependency
	// This is a simplified version - in production, refactor to avoid duplication
	fmt.Fprintf(os.Stderr, "\n🔐 Authentication Required\n")
	fmt.Fprintf(os.Stderr, "Enter your nokey PIN: ")

	// This is a placeholder - in the real implementation, import and use auth.Authenticate
	return fmt.Errorf("authentication not yet implemented for audit clear")
}
