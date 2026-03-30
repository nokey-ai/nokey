VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/nokey-ai/nokey/internal/version.Version=$(VERSION) \
           -X github.com/nokey-ai/nokey/internal/version.Commit=$(COMMIT) \
           -X github.com/nokey-ai/nokey/internal/version.Date=$(DATE)

.PHONY: build test lint install release clean coverage fmt vet check help

build:
	go build -ldflags "$(LDFLAGS)" -o nokey .
ifeq ($(shell uname),Darwin)
	@codesign -s - nokey 2>/dev/null && echo "Signed (ad-hoc) for Touch ID keychain access" || true
endif

test:
	go test ./...

lint:
	golangci-lint run

install:
	go install -ldflags "$(LDFLAGS)" .
ifeq ($(shell uname),Darwin)
	@GOBIN=$$(go env GOPATH)/bin && codesign -s - "$$GOBIN/nokey" 2>/dev/null || true
endif

release:
	goreleaser release --clean

coverage:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

fmt:
	gofmt -w .

vet:
	go vet ./...

check: test vet lint

clean:
	rm -f nokey coverage.out

help: ## Show available targets
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build     Build the nokey binary"
	@echo "  test      Run all tests"
	@echo "  lint      Run golangci-lint"
	@echo "  install   Install nokey to GOPATH/bin"
	@echo "  release   Create release with goreleaser"
	@echo "  coverage  Run tests with coverage report"
	@echo "  fmt       Format Go source files"
	@echo "  vet       Run go vet"
	@echo "  check     Run test + vet + lint (CI convenience)"
	@echo "  clean     Remove built binary and coverage output"
	@echo "  help      Show this help message"
