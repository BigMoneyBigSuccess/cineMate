FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY proto/go.mod proto/go.sum proto/
COPY movie-service/go.mod movie-service/go.sum movie-service/

RUN cd movie-service && go mod download

COPY proto/ proto/
COPY movie-service/ movie-service/

RUN cd movie-service && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/movie_service ./cmd/main

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/movie_service /app/movie_service
COPY movie-service/configs/config.docker.yaml /app/configs/config.docker.yaml

ENV MOVIE_SERVICE_CONFIG_PATH=/app/configs/config.docker.yaml

EXPOSE 50052

CMD ["/app/movie_service"]
