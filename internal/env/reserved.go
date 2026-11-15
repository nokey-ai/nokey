package env

import (
	"slices"
	"strings"
)

// Environment variables that make a program load, run or look up other
// code, read its configuration from elsewhere, or send its traffic
// elsewhere. Approving a command means approving that program talking to
// its usual hosts, so a caller may not set these. Matched
// case-insensitively, since Windows names are.
var (
	reservedNames = []string{
		// shells and loaders
		"PATH", "BASH_ENV", "ENV", "IFS", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND", "ZDOTDIR",
		"GCONV_PATH", "LOCPATH", "NLSPATH",
		// helpers programs start
		"PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "LESSOPEN", "LESSCLOSE", "MAKEFLAGS",
		"GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_PROXY_COMMAND", "GIT_PAGER", "GIT_DIR", "GIT_TEMPLATE_DIR",
		// language runtimes and toolchains
		"NODE_OPTIONS", "NODE_PATH", "GOFLAGS", "GOTOOLCHAIN", "CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
		"PERLLIB", "TCLLIBPATH", "RUSTC_WRAPPER",
		// configuration read from elsewhere
		"XDG_CONFIG_HOME", "CURL_HOME", "WGETRC",
		// traffic sent elsewhere, or trusted when it shouldn't be
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
	}
	reservedPrefixes = []string{
		"LD_", "DYLD_", "PYTHON", "PERL5", "RUBY", "LUA_", "GIT_SSH", "GIT_CONFIG",
		"DOTNET_", "NPM_CONFIG_", "GEM_", "BUNDLE_", "PIP_", "CARGO_",
	}
	// credentialSuffixes end the names tools read credentials from, such
	// as CARGO_REGISTRY_TOKEN or NPM_CONFIG__AUTH. No reserved variable
	// ends this way, so a secret may use such a name.
	credentialSuffixes = []string{"_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_AUTH"}
)

// Reserved reports whether name is a variable a caller may not set in a
// command's environment: see reservedNames.
func Reserved(name string) bool {
	upper := strings.ToUpper(name)
	if slices.Contains(reservedNames, upper) {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// ReservedSecretName reports whether a secret may not have name, because
// injecting it as an environment variable would be setting a Reserved
// variable. Credential-shaped names are allowed even under a reserved
// prefix.
func ReservedSecretName(name string) bool {
	upper := strings.ToUpper(name)
	for _, suffix := range credentialSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return false
		}
	}
	return Reserved(name)
}
