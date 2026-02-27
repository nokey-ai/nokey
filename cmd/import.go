package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import FILE",
	Short: "Import secrets from a .env file",
	Long: `Import secrets from a .env file into the OS keyring.

The file should contain KEY=VALUE pairs, one per line.
Lines starting with # are treated as comments.
After importing, consider deleting the .env file for security.

Example:
  nokey import .env`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

func init() {
	rootCmd.AddCommand(importCmd)
}

func runImport(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// Check file permissions
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Warn if file is readable by others (on Unix-like systems)
	mode := fileInfo.Mode()
	if mode&0044 != 0 {
		fmt.Fprintf(os.Stderr, "Warning: %s has overly permissive permissions (%v)\n", filePath, mode)
		fmt.Fprintf(os.Stderr, "Consider running: chmod 600 %s\n", filePath)
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Parse the file
	secrets := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Warning: skipping invalid line %d: %s\n", lineNum, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove matched-pair quotes if present
		if len(value) >= 2 && ((strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"))) {
			value = value[1 : len(value)-1]
		}

		if key == "" {
			fmt.Fprintf(os.Stderr, "Warning: skipping line %d with empty key\n", lineNum)
			continue
		}

		secrets[key] = value
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(secrets) == 0 {
		return fmt.Errorf("no valid secrets found in file")
	}

	// Store secrets
	store, err := getKeyring()
	if err != nil {
		return err
	}

	imported := 0
	importedKeys := make([]string, 0, len(secrets))
	failedKeys := make([]string, 0)

	for key, value := range secrets {
		if err := store.Set(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to import %s: %v\n", key, err)
			failedKeys = append(failedKeys, key)
			continue
		}
		imported++
		importedKeys = append(importedKeys, key)
	}

	// Record audit entry if audit logging is enabled
	if cfg.Audit.Enabled {
		errorMsg := ""
		if len(failedKeys) > 0 {
			errorMsg = fmt.Sprintf("failed to import %d secret(s): %v", len(failedKeys), failedKeys)
		}

		entry := audit.NewAuditEntry(
			"import",
			filePath,
			"none", // import operation doesn't require auth
			importedKeys,
			len(failedKeys) == 0,
			errorMsg,
		)

		// Record audit entry (ignore errors to not disrupt execution)
		if auditErr := audit.Record(store, entry); auditErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to record audit entry: %v\n", auditErr)
		}
	}

	fmt.Printf("Successfully imported %d secret(s) from %s\n", imported, filePath)
	fmt.Fprintf(os.Stderr, "\nSecurity tip: Consider deleting %s now that secrets are stored securely:\n", filePath)
	fmt.Fprintf(os.Stderr, "  rm %s\n", filePath)

	return nil
}
