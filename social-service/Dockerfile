FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY proto/go.mod proto/go.sum proto/
COPY clients/go.mod clients/go.sum clients/
COPY social-service/go.mod social-service/go.sum social-service/

RUN cd social-service && go mod download

COPY proto/ proto/
COPY clients/ clients/
COPY social-service/ social-service/

RUN cd social-service && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /social ./cmd

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /social /social
COPY social-service/configs/config.docker.yaml /configs/config.docker.yaml

EXPOSE 50053

ENTRYPOINT ["/social"]
