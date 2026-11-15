package env

import "testing"

func TestReserved(t *testing.T) {
	for _, name := range []string{
		"PATH", "Path", "BASH_ENV", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS",
		"PYTHONPATH", "GIT_SSH_COMMAND", "npm_config_script_shell",
		"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS",
		"XDG_CONFIG_HOME", "GIT_DIR", "GOTOOLCHAIN", "RUSTC_WRAPPER", "CARGO_BUILD_RUSTC", "PIP_INDEX_URL",
	} {
		if !Reserved(name) {
			t.Errorf("Reserved(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"OPENAI_API_KEY", "GITHUB_TOKEN", "MY_VAR", "HOME"} {
		if Reserved(name) {
			t.Errorf("Reserved(%q) = true, want false", name)
		}
	}
}

func TestReservedSecretName(t *testing.T) {
	for _, name := range []string{"PATH", "BASH_ENV", "LD_PRELOAD", "HTTPS_PROXY", "PIP_INDEX_URL", "GIT_ASKPASS"} {
		if !ReservedSecretName(name) {
			t.Errorf("ReservedSecretName(%q) = false, want true", name)
		}
	}
	// Credential variables under a reserved prefix stay usable.
	for _, name := range []string{"CARGO_REGISTRY_TOKEN", "GEM_HOST_API_KEY", "NPM_CONFIG__AUTH", "PYTHON_SDK_SECRET", "GITHUB_TOKEN"} {
		if ReservedSecretName(name) {
			t.Errorf("ReservedSecretName(%q) = true, want false", name)
		}
	}
}
