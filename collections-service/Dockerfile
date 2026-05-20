FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/movie_collection ./cmd/main

FROM alpine:3.20

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app \
    && apk add --no-cache ca-certificates

COPY --from=builder /out/movie_collection /app/movie_collection
COPY configs /app/configs

USER app

ENV MOVIE_COLLECTION_CONFIG_PATH=/app/configs/config.docker.yaml

EXPOSE 8080

CMD ["/app/movie_collection"]
