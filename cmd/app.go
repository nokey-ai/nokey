package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/nokey-ai/nokey/internal/audit"
	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/spf13/cobra"
)

// App holds shared dependencies for CLI commands.
type App struct {
	Config     *config.Config
	GetKeyring func() (*keyring.Store, error)
}

type appKey struct{}

// AppFromCmd retrieves the App from the command's context.
func AppFromCmd(cmd *cobra.Command) *App {
	if cmd != nil {
		if ctx := cmd.Context(); ctx != nil {
			if v := ctx.Value(appKey{}); v != nil {
				return v.(*App)
			}
		}
	}
	// Fallback for tests or commands that run before PersistentPreRun.
	return &App{Config: cfg, GetKeyring: getKeyring}
}

// RecordAudit logs an audit entry if auditing is enabled.
// Consolidates the identical audit recording pattern used across CLI commands.
func (a *App) RecordAudit(store *keyring.Store, op, command, authMethod string, secretNames []string, success bool, errMsg string) {
	if a.Config == nil || !a.Config.Audit.Enabled {
		return
	}
	entry := audit.NewAuditEntry(op, command, authMethod, secretNames, success, errMsg)
	if err := audit.Record(store, entry, a.Config.Audit.MaxEntries, a.Config.Audit.RetentionDays); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to record audit entry: %v\n", err)
	}
}

// setAppContext attaches the App to a command's context.
func setAppContext(cmd *cobra.Command) {
	app := &App{Config: cfg, GetKeyring: getKeyring}
	ctx := context.WithValue(cmd.Context(), appKey{}, app)
	cmd.SetContext(ctx)
}
