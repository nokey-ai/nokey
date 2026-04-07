package integration

import (
	"github.com/mark3labs/mcp-go/server"
	"github.com/nokey-ai/nokey/internal/policy"
)

// SecretMapping describes how a secret maps to an HTTP header.
type SecretMapping struct {
	SecretName string // keyring key, e.g. "GITHUB_TOKEN"
	HeaderName string // e.g. "Authorization"
	HeaderTmpl string // fmt verb for the secret value, e.g. "Bearer %s"
}

// Deps holds shared dependencies injected into integration tools.
type Deps struct {
	GetSecret func(name string) (string, error)
	// GetPolicy returns the current policy, reloading from disk when the
	// source file has changed. Called per-request; must be safe for
	// concurrent use. A nil return value or nil GetPolicy means allow-all.
	GetPolicy func() *policy.Policy
	Requester *server.MCPServer
	AuditFn   func(op, target, secrets string, ok bool, errMsg string)
	UseToken  func(id string, secrets []string) error // nil = no token support
}

// Integration is the interface that each service integration implements.
type Integration interface {
	Name() string
	Description() string
	SecretMappings() []SecretMapping
	Tools(deps Deps) []server.ServerTool
}

var registry []Integration

// Register adds an integration to the global registry.
func Register(i Integration) {
	registry = append(registry, i)
}

// All returns all registered integrations.
func All() []Integration {
	return registry
}
