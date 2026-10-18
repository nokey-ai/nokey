package cmd

import (
	"os"
	"sync"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	Long: `Generate a shell completion script for the specified shell.

To load completions:

  bash:
    source <(nokey completion bash)
    # or add to ~/.bashrc:
    echo 'source <(nokey completion bash)' >> ~/.bashrc

  zsh:
    source <(nokey completion zsh)
    # or install to fpath:
    nokey completion zsh > "${fpath[1]}/_nokey"

  fish:
    nokey completion fish | source
    # or install persistently:
    nokey completion fish > ~/.config/fish/completions/nokey.fish

  powershell:
    nokey completion powershell | Out-String | Invoke-Expression`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
	// Registered lazily: some flags are defined in init funcs of files that
	// sort after this one, and cobra rejects completions for unknown flags.
	cobra.OnInitialize(registerFlagCompletions)
}

// auditOperations lists the operation names nokey records in the audit log.
var auditOperations = []string{
	"exec", "exec:policy_deny", "set", "delete", "import", "export",
	"mcp:exec", "mcp:exec:approval",
	"mcp:exec_with_secrets", "mcp:exec_with_secrets:approval",
	"mcp:list_secrets", "mcp:start_proxy", "mcp:stop_proxy",
	"mcp:mint_token", "mcp:mint_token:approval", "mcp:revoke_token",
	"mcp:token_use", "mcp:auto_mint",
}

var registerCompletionsOnce sync.Once

// registerFlagCompletions adds static value completion for enum-like flags.
// Secret names are deliberately not completed: listing them opens the
// keyring, which can show an unlock dialog (a locked dedicated keychain,
// a locked Secret Service collection) every time the user presses Tab.
// For the same reason PersistentPreRun skips the keychain migration hint
// for completion requests (see root.go).
func registerFlagCompletions() {
	registerCompletionsOnce.Do(func() {
		fixed := func(values ...string) cobra.CompletionFunc {
			return cobra.FixedCompletions(values, cobra.ShellCompDirectiveNoFileComp)
		}
		providers := fixed("github", "custom", "generic")

		for _, r := range []struct {
			cmd  *cobra.Command
			flag string
			fn   cobra.CompletionFunc
		}{
			{exportCmd, "shell", fixed("bash", "zsh", "fish", "powershell")},
			{execCmd, "auth-method", fixed("pin", "oauth", "both", "none")},
			{auditExportCmd, "format", fixed("json", "csv")},
			{auditListCmd, "operation", fixed(auditOperations...)},
			{auditExportCmd, "operation", fixed(auditOperations...)},
			{authOAuthSetupCmd, "provider", providers},
			{authOAuthRefreshCmd, "provider", providers},
			{authOAuthLogoutCmd, "provider", providers},
		} {
			_ = r.cmd.RegisterFlagCompletionFunc(r.flag, r.fn)
		}
	})
}
