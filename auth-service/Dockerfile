FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY proto/go.mod proto/go.sum proto/
COPY clients/go.mod clients/go.sum clients/
COPY auth-service/go.mod auth-service/go.sum auth-service/

RUN cd auth-service && go mod download

COPY proto/ proto/
COPY clients/ clients/
COPY auth-service/ auth-service/

RUN cd auth-service && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /auth ./cmd

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /auth /auth
COPY auth-service/configs/config.docker.yaml /configs/config.docker.yaml

EXPOSE 50051

ENTRYPOINT ["/auth"]
