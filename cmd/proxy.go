package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/spf13/cobra"
)

var proxyAddr string

// makeSignalChan creates the channel for OS signal notification. Overridable for testing.
var makeSignalChan = func() chan os.Signal {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	return sig
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "HTTP/HTTPS intercept proxy for secret injection into API requests",
	Long: `Run a local proxy that intercepts outbound HTTP/HTTPS requests and
injects secrets into request headers based on rules in policies.yaml.

AI agents point their HTTP client at the proxy and never handle
credentials directly. HTTPS interception uses a local CA certificate.

Subcommands:
  start    - Start the proxy (foreground)
  init-ca  - Generate the CA certificate
  trust-ca - Print OS-specific CA trust instructions`,
}

var proxyStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server (foreground)",
	Long: `Start the local HTTP/HTTPS proxy server. The proxy injects secrets into
request headers based on proxy rules defined in ~/.config/nokey/policies.yaml.

Secrets are fetched once at startup and held in memory. The proxy listens on
localhost only.

Example policies.yaml proxy section:
  proxy:
    rules:
      - hosts: ["api.openai.com"]
        headers:
          Authorization: "Bearer $OPENAI_API_KEY"
      - hosts: ["*.example.com"]
        headers:
          x-api-key: "$EXAMPLE_API_KEY"
        approval: never`,
	RunE: runProxyStart,
}

var proxyInitCACmd = &cobra.Command{
	Use:   "init-ca",
	Short: "Generate the local proxy CA certificate",
	Long: `Create a local CA certificate used for HTTPS interception (MITM).
The CA is stored in ~/.config/nokey/ca/.

If the CA already exists, this command prints its path without regenerating.`,
	RunE: runProxyInitCA,
}

var proxyTrustCACmd = &cobra.Command{
	Use:   "trust-ca",
	Short: "Print OS-specific instructions to trust the proxy CA",
	Long:  `Print platform-specific instructions for adding the nokey proxy CA to the system trust store.`,
	RunE:  runProxyTrustCA,
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyInitCACmd)
	proxyCmd.AddCommand(proxyTrustCACmd)

	proxyStartCmd.Flags().StringVar(&proxyAddr, "addr", "127.0.0.1:0", "Address to listen on (default: random port on localhost)")
}

func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, ".config", "nokey"), nil
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	// Load policy.
	pol, err := policy.Load(configDir)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	rules := pol.ProxyRules()
	if len(rules) == 0 {
		return fmt.Errorf("no proxy rules found in %s/policies.yaml\n\nAdd a proxy section to your policies.yaml:\n  proxy:\n    rules:\n      - hosts: [\"api.example.com\"]\n        headers:\n          Authorization: \"Bearer $SECRET_NAME\"", configDir)
	}

	// Load or create CA.
	ca, err := proxy.LoadOrCreateCA(configDir)
	if err != nil {
		return fmt.Errorf("failed to load/create CA: %w", err)
	}

	// Collect all secret names referenced by proxy rules.
	secretNames := proxy.CollectSecretNames(rules)

	// Fetch secrets from keyring.
	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	secrets := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		val, err := store.Get(name)
		if err != nil {
			return fmt.Errorf("failed to get secret %q: %w", name, err)
		}
		secrets[name] = val
	}

	// Create and start server.
	srv := proxy.NewServer(ca, rules, secrets, pol, recordAudit)

	addr, err := srv.Start(proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	fmt.Printf("nokey proxy listening on %s\n", addr)
	fmt.Printf("\nTo use:\n")
	fmt.Printf("  export http_proxy=http://%s\n", addr)
	fmt.Printf("  export https_proxy=http://%s\n", addr)
	fmt.Printf("\nInjecting headers for %d rule(s) covering %d secret(s)\n", len(rules), len(secretNames))
	fmt.Printf("CA cert: %s\n", filepath.Join(configDir, "ca", "ca-cert.pem"))
	fmt.Printf("\nPress Ctrl+C to stop\n")

	// Block on SIGINT/SIGTERM.
	sig := makeSignalChan()
	<-sig

	fmt.Printf("\nShutting down proxy...\n")
	if err := srv.Stop(context.Background()); err != nil {
		return fmt.Errorf("failed to stop proxy: %w", err)
	}
	fmt.Println("Proxy stopped.")
	return nil
}

func runProxyInitCA(cmd *cobra.Command, args []string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	ca, err := proxy.LoadOrCreateCA(configDir)
	if err != nil {
		return fmt.Errorf("failed to create CA: %w", err)
	}
	_ = ca // Just need side effect of creating files.

	certPath := filepath.Join(configDir, "ca", "ca-cert.pem")
	fmt.Printf("CA certificate: %s\n", certPath)
	fmt.Printf("\nTo trust this CA, run:\n  nokey proxy trust-ca\n")
	return nil
}

func runProxyTrustCA(cmd *cobra.Command, args []string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	certPath := filepath.Join(configDir, "ca", "ca-cert.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate not found — run 'nokey proxy init-ca' first")
	}

	fmt.Printf("CA certificate: %s\n\n", certPath)

	switch runtime.GOOS {
	case "darwin":
		fmt.Println("macOS — add to system trust store:")
		fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "linux":
		fmt.Println("Linux — add to system trust store:")
		fmt.Printf("  sudo cp %s /usr/local/share/ca-certificates/nokey-proxy.crt\n", certPath)
		fmt.Println("  sudo update-ca-certificates")
	default:
		fmt.Println("Windows — add to system trust store:")
		fmt.Printf("  certutil -addstore -f \"ROOT\" %s\n", certPath)
	}

	fmt.Println("\nOr use per-request trust:")
	fmt.Printf("  curl --cacert %s https://example.com\n", certPath)
	fmt.Println("\nOr set the environment variable:")
	fmt.Printf("  export SSL_CERT_FILE=%s\n", certPath)

	// Show which secrets the proxy rules reference.
	pol, err := policy.Load(configDir)
	if err == nil && pol != nil {
		rules := pol.ProxyRules()
		if len(rules) > 0 {
			var hosts []string
			for _, r := range rules {
				hosts = append(hosts, r.Hosts...)
			}
			fmt.Printf("\nConfigured proxy hosts: %s\n", strings.Join(hosts, ", "))
		}
	}

	return nil
}
