# Images for netcrawl-server (default) and netcrawl-agent.
#   docker build -t netcrawl-server .
#   docker build --target agent -t netcrawl-agent .
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X netcrawler/internal/version.Version=${VERSION}" \
    -o /out/ ./cmd/netcrawl-server ./cmd/netcrawl-agent

# The agent needs to see the network it scans, so run it with
# network_mode: host (see deploy/testenv).
FROM gcr.io/distroless/static-debian12:nonroot AS agent
COPY --from=build /out/netcrawl-agent /usr/local/bin/netcrawl-agent
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/netcrawl-agent"]
CMD ["--config", "/data/agent.json"]

FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/netcrawl-server /usr/local/bin/netcrawl-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/netcrawl-server"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
