FROM golang:1.26-alpine AS builder

WORKDIR /build

# Local replace targets — go.mod/go.sum first so module download is cacheable.
COPY proto/go.mod proto/go.sum proto/
COPY clients/go.mod clients/go.sum clients/
COPY api-gateway/go.mod api-gateway/go.sum api-gateway/

RUN cd api-gateway && go mod download

# Now bring in the actual source.
COPY proto/ proto/
COPY clients/ clients/
COPY api-gateway/ api-gateway/

RUN cd api-gateway && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /gateway ./cmd

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /gateway /gateway
COPY api-gateway/configs/config.docker.yaml /configs/config.docker.yaml

EXPOSE 8080

ENTRYPOINT ["/gateway", "-config", "/configs/config.docker.yaml"]
