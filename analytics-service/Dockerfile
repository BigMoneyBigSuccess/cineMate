FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY proto/go.mod proto/go.sum proto/
COPY clients/go.mod clients/go.sum clients/
COPY analytics-service/go.mod analytics-service/go.sum analytics-service/

RUN cd analytics-service && go mod download

COPY proto/ proto/
COPY clients/ clients/
COPY analytics-service/ analytics-service/

RUN cd analytics-service && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /analytics \
    ./cmd/main

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /analytics /analytics
COPY analytics-service/configs/config.docker.yaml /configs/config.docker.yaml

ENV ANALYTICS_CONFIG_PATH=/configs/config.docker.yaml

EXPOSE 50054

ENTRYPOINT ["/analytics"]
