package version

// Version, Commit, and Date are set via -ldflags at build time:
//
//	go build -ldflags "-X github.com/nokey-ai/nokey/internal/version.Version=1.0.0 \
//	  -X github.com/nokey-ai/nokey/internal/version.Commit=abc1234 \
//	  -X github.com/nokey-ai/nokey/internal/version.Date=2024-01-01"
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
