FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY analytics-service/ analytics-service/

RUN cd analytics-service && CGO_ENABLED=0 GOOS=linux go build \
    -mod=vendor \
    -trimpath -ldflags="-s -w" \
    -o /analytics \
    ./cmd/main

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /analytics /analytics
COPY analytics-service/configs/config.docker.yaml /configs/config.docker.yaml

ENV ANALYTICS_CONFIG_PATH=/configs/config.docker.yaml

EXPOSE 8081

ENTRYPOINT ["/analytics"]
