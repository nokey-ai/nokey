VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -X github.com/nokey-ai/nokey/internal/version.Version=$(VERSION)

.PHONY: build test lint install release clean

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

clean:
	rm -f nokey
