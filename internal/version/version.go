package version

// Version is set via -ldflags at build time:
//
//	go build -ldflags "-X github.com/nokey-ai/nokey/internal/version.Version=1.0.0"
var Version = "dev"
