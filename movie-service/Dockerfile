FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY proto/go.mod proto/go.sum proto/
COPY movie-service/go.mod movie-service/go.sum movie-service/
RUN cd movie-service && go mod download

COPY proto/ proto/
COPY movie-service/ movie-service/

RUN cd movie-service && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/movie_service ./cmd/main

FROM alpine:3.20

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app \
    && apk add --no-cache ca-certificates

COPY --from=builder /out/movie_service /app/movie_service
COPY --from=builder /src/movie-service/configs /app/configs

USER app

ENV MOVIE_SERVICE_CONFIG_PATH=/app/configs/config.local.yaml

EXPOSE 8080

CMD ["/app/movie_service"]
