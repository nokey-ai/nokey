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
	"time"

	"github.com/nokey-ai/nokey/internal/config"
	"github.com/nokey-ai/nokey/internal/keyring"
	"github.com/nokey-ai/nokey/internal/policy"
	"github.com/nokey-ai/nokey/internal/proxy"
	"github.com/spf13/cobra"
)

var (
	proxyAddr     string
	trustCASystem bool
)

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
  trust-ca - Print CA trust instructions`,
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
The certificate is stored in ~/.config/nokey/ca/ and its key in the keyring.

The CA can sign only for the hosts of the proxy rules in the approved
policies.yaml, so add those first. If a CA that covers them already exists,
this command prints its path without regenerating.`,
	RunE: runProxyInitCA,
}

var proxyTrustCACmd = &cobra.Command{
	Use:   "trust-ca",
	Short: "Print instructions to trust the proxy CA",
	Long: `Print how to make the commands that use the proxy trust its CA, through
their environment. --system adds the commands for the system trust store,
which is not recommended: every program on the machine would then accept
the CA, and nokey replaces it when the proxy hosts change and every 90 days.`,
	RunE: runProxyTrustCA,
}

func init() {
	rootCmd.AddCommand(proxyCmd)
	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyInitCACmd)
	proxyCmd.AddCommand(proxyTrustCACmd)

	proxyTrustCACmd.Flags().BoolVar(&trustCASystem, "system", false, "Also print the commands for the system trust store (not recommended)")
	proxyStartCmd.Flags().StringVar(&proxyAddr, "addr", "127.0.0.1:0", "Loopback address to listen on (default: random port on localhost)")
}

func getConfigDir() (string, error) {
	return config.ConfigDir()
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	// Validate before anything touches the keyring: an address we are going to
	// refuse should not cost the user a Touch ID prompt or pull secrets into
	// memory first.
	if err := proxy.ValidateListenAddr(proxyAddr); err != nil {
		return err
	}

	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	// Load policy.
	pol, err := loadApprovedPolicy(store, configDir)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	rules := pol.ProxyRules()
	if len(rules) == 0 {
		return errNoProxyRules(configDir)
	}

	// Load or create CA.
	ca, err := proxy.LoadOrCreateCA(configDir, caKeys{store}, proxy.RuleHosts(rules))
	if err != nil {
		return fmt.Errorf("failed to load/create CA: %w", err)
	}

	// Collect all secret names referenced by proxy rules.
	secretNames := proxy.CollectSecretNames(rules)

	// The proxy injects these secrets into requests for as long as it runs,
	// so the person at the machine must approve starting it.
	if err := confirmHuman(cmdContext(cmd), store, fmt.Sprintf("start the proxy with secrets %s", strings.Join(secretNames, ", ")), false); err != nil {
		return err
	}

	// Fetch secrets from keyring.
	secrets := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		val, err := store.Get(name)
		if err != nil {
			return fmt.Errorf("failed to get secret %q: %w", name, err)
		}
		secrets[name] = val
	}

	// Create and start server.
	srv := proxy.NewServer(ca, rules, secrets, recordAudit)

	addr, err := srv.Start(proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	fmt.Printf("nokey proxy listening on %s\n", addr)
	fmt.Printf("\nTo use (the URL holds this run's proxy password; clients without it are refused):\n")
	fmt.Printf("  export http_proxy=%s\n", srv.URL())
	fmt.Printf("  export https_proxy=%s\n", srv.URL())
	fmt.Printf("\nHeaders are injected only into HTTPS requests, on port 443 unless a rule lists ports.\n")
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

// caKeyName is the keyring entry that holds the proxy CA's private key.
const caKeyName = "__nokey_proxy_ca_key__"

// caKeys keeps the proxy CA key in the keyring, as one of nokey's own
// entries: it is no secret to inject, and `nokey list` doesn't show it.
type caKeys struct{ store *keyring.Store }

func (k caKeys) CAKey() (string, error) {
	keyPEM, err := k.store.GetInternal(caKeyName)
	if keyring.IsNotFound(err) {
		return "", nil
	}
	return keyPEM, err
}

func (k caKeys) SetCAKey(keyPEM string) error {
	return k.store.SetInternal(caKeyName, keyPEM)
}

// errNoProxyRules explains how to add the proxy rules a command needs.
func errNoProxyRules(configDir string) error {
	return fmt.Errorf("no proxy rules found in %s/policies.yaml\n\nAdd a proxy section to your policies.yaml:\n  proxy:\n    rules:\n      - hosts: [\"api.example.com\"]\n        headers:\n          Authorization: \"Bearer $SECRET_NAME\"", configDir)
}

func runProxyInitCA(cmd *cobra.Command, args []string) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	store, err := getKeyring()
	if err != nil {
		return fmt.Errorf("failed to open keyring: %w", err)
	}

	// The CA may sign only for the hosts of the approved proxy rules.
	pol, err := loadApprovedPolicy(store, configDir)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}
	rules := pol.ProxyRules()
	if len(rules) == 0 {
		return errNoProxyRules(configDir)
	}

	ca, err := proxy.LoadOrCreateCA(configDir, caKeys{store}, proxy.RuleHosts(rules))
	if err != nil {
		return fmt.Errorf("failed to create CA: %w", err)
	}

	certPath := filepath.Join(configDir, "ca", "ca-cert.pem")
	fmt.Printf("CA certificate: %s\n", certPath)
	fmt.Printf("\nIt can sign only for your proxy rule hosts, and its key is in the keyring.\n")
	fmt.Printf("nokey replaces it when those hosts change and before it expires (%s).\n", ca.Cert.NotAfter.Format(time.DateOnly))
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

	fmt.Println("Trust it per process, in the environment of the commands that use the proxy:")
	fmt.Printf("  export NODE_EXTRA_CA_CERTS=%s   # Node.js: added to its own roots\n", certPath)
	fmt.Printf("  export SSL_CERT_FILE=%s         # OpenSSL, Go, curl\n", certPath)
	fmt.Printf("  export REQUESTS_CA_BUNDLE=%s    # Python requests\n", certPath)
	fmt.Printf("  curl --cacert %s https://api.example.com\n", certPath)
	fmt.Println("\nSSL_CERT_FILE, REQUESTS_CA_BUNDLE and --cacert replace the default roots. Hosts with no")
	fmt.Println("proxy rule pass through the proxy with their own certificates, so to reach those as well")
	fmt.Println("point the variable at a file holding your system roots followed by this certificate.")
	fmt.Println("`nokey exec --isolate` sets these variables for the command it runs.")

	if trustCASystem {
		fmt.Println("\nSystem trust store (not recommended):")
		switch runtime.GOOS {
		case "darwin":
			fmt.Printf("  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
		case "linux":
			fmt.Printf("  sudo cp %s /usr/local/share/ca-certificates/nokey-proxy.crt\n", certPath)
			fmt.Println("  sudo update-ca-certificates")
		default:
			fmt.Printf("  certutil -addstore -f \"ROOT\" %s\n", certPath)
		}
		fmt.Println("Every program on the machine then accepts this CA for your proxy rule hosts, and you")
		fmt.Println("have to repeat this, and remove the old certificate, each time nokey replaces the CA.")
	} else {
		fmt.Println("\nSystem-wide trust is not recommended: every program on the machine would accept this CA,")
		fmt.Println("and nokey replaces it when your proxy hosts change and every 90 days. Pass --system to")
		fmt.Println("print those commands anyway.")
	}

	// Show which secrets the proxy rules reference.
	pol, err := policy.Load(configDir)
	if err == nil && pol != nil {
		rules := pol.ProxyRules()
		if len(rules) > 0 {
			fmt.Printf("\nConfigured proxy hosts: %s\n", strings.Join(proxy.RuleHosts(rules), ", "))
		}
	}

	return nil
}
