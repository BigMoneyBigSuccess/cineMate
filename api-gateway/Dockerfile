FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY api-gateway/ api-gateway/

RUN cd api-gateway && CGO_ENABLED=0 GOOS=linux go build \
    -mod=vendor \
    -trimpath -ldflags="-s -w" \
    -o /gateway ./cmd

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /gateway /gateway
COPY api-gateway/configs/config.docker.yaml /configs/config.docker.yaml

EXPOSE 8080

ENTRYPOINT ["/gateway", "-config", "/configs/config.docker.yaml"]
