VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/nokey-ai/nokey/internal/version.Version=$(VERSION) \
           -X github.com/nokey-ai/nokey/internal/version.Commit=$(COMMIT) \
           -X github.com/nokey-ai/nokey/internal/version.Date=$(DATE)

.PHONY: build test lint install release clean coverage fmt vet help

build:
	go build -ldflags "$(LDFLAGS)" -o nokey .

test:
	go test ./...

lint:
	golangci-lint run

install:
	go install -ldflags "$(LDFLAGS)" .

release:
	goreleaser release --clean

coverage:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

fmt:
	gofmt -w .

vet:
	go vet ./...

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
	@echo "  clean     Remove built binary and coverage output"
	@echo "  help      Show this help message"
