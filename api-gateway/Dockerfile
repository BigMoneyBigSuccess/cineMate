FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files from all services
COPY auth-service/go.mod auth-service/go.sum ./auth-service/
COPY collections-service/go.mod collections-service/go.sum ./collections-service/
COPY api-gateway/go.mod api-gateway/go.sum ./api-gateway/

# Copy source code
COPY auth-service/api ./auth-service/api
COPY auth-service/internal ./auth-service/internal
COPY collections-service/api ./collections-service/api
COPY api-gateway ./api-gateway

WORKDIR /app/api-gateway

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o api-gateway ./cmd/main.go

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/api-gateway/api-gateway .
COPY --from=builder /app/api-gateway/configs/config.docker.yaml ./config.yaml

EXPOSE 8080

CMD ["./api-gateway", "-config", "./config.yaml"]
