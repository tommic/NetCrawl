BINS=netcrawler result2csv result2md

.PHONY: all build test vet fmt check clean

all: build

build:
	go build -o netcrawler ./cmd/netcrawler
	go build -o result2csv ./cmd/result2csv
	go build -o result2md ./cmd/result2md

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# Same checks as CI.
check:
	@test -z "$$(gofmt -l .)" || (echo "Not gofmt-formatted:"; gofmt -l .; exit 1)
	go vet ./...
	go test -race ./...

clean:
	rm -f $(BINS)
