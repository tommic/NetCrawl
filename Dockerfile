# netcrawl-server image. Build: docker build -t netcrawl-server .
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X netcrawler/internal/version.Version=${VERSION}" \
    -o /out/netcrawl-server ./cmd/netcrawl-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/netcrawl-server /usr/local/bin/netcrawl-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/netcrawl-server"]
CMD ["serve", "--listen", "0.0.0.0:8080"]
