BINS=netcrawler result2csv result2md

.PHONY: all build clean

all: build

build:
	go build -o netcrawler ./cmd/netcrawler
	go build -o result2csv ./cmd/result2csv
	go build -o result2md ./cmd/result2md

clean:
	rm -f $(BINS)
