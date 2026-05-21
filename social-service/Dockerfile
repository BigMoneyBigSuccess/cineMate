FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY social-service/ social-service/

RUN cd social-service && CGO_ENABLED=0 GOOS=linux go build \
    -mod=vendor \
    -trimpath -ldflags="-s -w" \
    -o /social ./cmd

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /social /social
COPY social-service/configs/config.docker.yaml /configs/config.docker.yaml

EXPOSE 50053

ENTRYPOINT ["/social"]
