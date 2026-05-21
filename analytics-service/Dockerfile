FROM golang:1.26-alpine AS builder

WORKDIR /build

# proto and clients are local replace dependencies; they must sit at ../proto
# and ../clients relative to the module root, so copy them before downloading modules.
COPY proto ./proto
COPY clients ./clients

COPY analytics-service/go.mod analytics-service/go.sum ./analytics-service/
RUN cd analytics-service && go mod download

COPY analytics-service/ ./analytics-service/

RUN cd analytics-service && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /analytics \
    ./cmd/main

# ─────────────────────────────────────────────────────────────────────────────

FROM alpine:3.21

RUN addgroup -S analytics && adduser -S analytics -G analytics

COPY --from=builder /analytics /analytics
COPY analytics-service/configs/config.local.yaml /configs/config.local.yaml

USER analytics

ENV ANALYTICS_CONFIG_PATH=/configs/config.local.yaml

EXPOSE 8081

ENTRYPOINT ["/analytics"]
