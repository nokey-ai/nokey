package cmd

import (
	"fmt"
	"os"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/version"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	backend string
	cfg     *config.Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "nokey",
	Short: "Securely manage secrets for AI coding assistants",
	Long: `nokey stores credentials in OS-native secure storage and injects them
as environment variables when running subprocesses, so AI assistants can use
secrets without ever seeing the actual values.`,
	SilenceUsage: true,
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of nokey",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("nokey %s\n", version.Version)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&backend, "backend", "", "Keyring backend (default: system default)")
	rootCmd.AddCommand(versionCmd)
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	var err error
	cfg, err = config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config: %v\n", err)
		cfg = config.DefaultConfig()
	}

	// Override config with environment variable if set
	if envBackend := os.Getenv("NOKEY_BACKEND"); envBackend != "" {
		cfg.DefaultBackend = envBackend
	}

	// Override config with flag if set
	if backend != "" {
		cfg.DefaultBackend = backend
	}
}

// getKeyring returns a keyring store using the current configuration.
// It is a variable so tests can override it.
var getKeyring = func() (*keyring.Store, error) {
	return keyring.New(cfg.DefaultBackend, cfg.ServiceName)
}
