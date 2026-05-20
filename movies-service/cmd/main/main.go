package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"movie_collection/api/proto/moviecollectionv1"
	httpadapter "movie_collection/internal/adapters/http"
	postgresadapter "movie_collection/internal/adapters/postgres"
	redisadapter "movie_collection/internal/adapters/redis"
	appconfig "movie_collection/internal/config"
	"movie_collection/internal/core/ports"
	"movie_collection/internal/core/usecase"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := appconfig.Load(resolveConfigPath())
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("Loaded config: %s", cfg)

	db, err := openPostgres(ctx, cfg.Postgres.URL)
	if err != nil {
		return err
	}
	defer db.Close()

	redisClient, err := openRedis(ctx, cfg.Redis)
	if err != nil {
		return err
	}
	if redisClient != nil {
		defer func() {
			_ = redisClient.Close()
		}()
	}

	movieRepo := postgresadapter.NewMovieRepository(db)
	var repository ports.MovieRepository = movieRepo
	repository = redisadapter.NewMovieCache(repository, redisClient, cfg.Cache.MovieTTL, cfg.Cache.MovieListTTL)

	watchlistRepo := postgresadapter.NewWatchlistRepository(db)

	handler := httpadapter.NewMovieHandler(
		usecase.NewMovieUseCase(repository),
		usecase.NewWatchlistUseCase(watchlistRepo),
	)

	grpcServer := grpc.NewServer()
	moviecollectionv1.RegisterMovieCatalogServiceServer(grpcServer, handler)
	moviecollectionv1.RegisterMovieCatalogAdminServiceServer(grpcServer, handler)
	moviecollectionv1.RegisterWatchlistServiceServer(grpcServer, handler)
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", cfg.GRPC.Addr)
	if err != nil {
		return fmt.Errorf("listen grpc on %s: %w", cfg.GRPC.Addr, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		shutdownGRPCServer(grpcServer, cfg.ShutdownTimeout)
	}()

	log.Printf("gRPC server listening on %s", cfg.GRPC.Addr)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve grpc: %w", err)
	}

	return nil
}

func openPostgres(ctx context.Context, databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return db, nil
}

func openRedis(ctx context.Context, cfg appconfig.RedisConfig) (*redis.Client, error) {
	if cfg.Addr == "" {
		log.Print("Redis is not configured, movie cache is disabled")
		return nil, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return client, nil
}

func shutdownGRPCServer(server *grpc.Server, timeout time.Duration) {
	done := make(chan struct{})

	go func() {
		server.GracefulStop()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
		server.Stop()
	}
}

func resolveConfigPath() string {
	defaultPath := appconfig.DefaultPath
	if value := os.Getenv("MOVIE_COLLECTION_CONFIG_PATH"); value != "" {
		defaultPath = value
	}

	configPath := flag.String("config", defaultPath, "path to YAML config file")
	flag.Parse()

	return *configPath
}
