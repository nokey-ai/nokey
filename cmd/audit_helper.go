package cmd

import (
	"github.com/nokey-ai/nokey/internal/audit"
)

// recordAudit logs an audit entry if auditing is enabled.
// Used by CLI commands that need audit recording (e.g., proxy start).
func recordAudit(operation, command, target string, success bool, errMsg string) {
	if cfg == nil || !cfg.Audit.Enabled {
		return
	}

	store, err := getKeyring()
	if err != nil {
		return
	}

	secretNames := []string{target}
	entry := audit.NewAuditEntry(operation, command, "keyring_acl", secretNames, success, errMsg)
	_ = audit.Record(store, entry, cfg.Audit.MaxEntries, cfg.Audit.RetentionDays)
}
