BINS=netcrawler result2csv result2md netcrawl-server netcrawl-agent
VERSION ?= dev
# Store and E2E tests share NETCRAWL_TEST_DATABASE_URL: run packages one at a time then.
TESTFLAGS=-race $(if $(NETCRAWL_TEST_DATABASE_URL),-p 1,)
LDFLAGS=-ldflags "-X netcrawler/internal/version.Version=$(VERSION)"

.PHONY: all build agents test vet fmt check e2e clean

all: build

build:
	go build -o netcrawler ./cmd/netcrawler
	go build -o result2csv ./cmd/result2csv
	go build -o result2md ./cmd/result2md
	go build $(LDFLAGS) -o netcrawl-server ./cmd/netcrawl-server
	go build $(LDFLAGS) -o netcrawl-agent ./cmd/netcrawl-agent

test:
	go test $(TESTFLAGS) ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Same checks as CI.
check:
	@test -z "$$(gofmt -l .)" || (echo "Not gofmt-formatted:"; gofmt -l .; exit 1)
	go vet ./...
	go test $(TESTFLAGS) ./...

# Loopback pilot acceptance tests (E2E-01..07) with evidence report.
# Uses PostgreSQL if NETCRAWL_TEST_DATABASE_URL is set.
e2e:
	NETCRAWL_E2E_REPORT=$(CURDIR)/e2e-report.md go test -count=1 -v $(LDFLAGS) ./internal/e2e
	@echo "Evidence report: e2e-report.md"

# Agent binaries the server hands out to the installer (--agent-dir dist/agent).
agents:
	mkdir -p dist/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X netcrawler/internal/version.Version=$(VERSION)" -o dist/agent/netcrawl-agent-linux-amd64 ./cmd/netcrawl-agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X netcrawler/internal/version.Version=$(VERSION)" -o dist/agent/netcrawl-agent-linux-arm64 ./cmd/netcrawl-agent

clean:
	rm -f $(BINS)
	rm -rf dist
