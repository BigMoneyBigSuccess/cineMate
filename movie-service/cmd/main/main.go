package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	grpcadapter "github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/adapters/grpc"
	postgresadapter "github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/adapters/postgres"
	redisadapter "github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/adapters/redis"
	appconfig "github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/config"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/syncer"
	"github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"

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

	pool, err := postgresadapter.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()

	redisClient, err := openRedis(ctx, cfg.Redis)
	if err != nil {
		return err
	}
	if redisClient != nil {
		defer func() {
			_ = redisClient.Close()
		}()
	}

	movieRepo := postgresadapter.NewMovieRepository(pool)
	var repository ports.MovieRepository = movieRepo
	repository = redisadapter.NewMovieCache(repository, redisClient, cfg.Cache.MovieTTL, cfg.Cache.MovieListTTL)

	movieUseCase := usecase.NewMovieUseCase(repository)

	if cfg.Syncer.Enabled {
		client := syncer.NewClient(cfg.Syncer.BaseURL, cfg.Syncer.APIKey, cfg.Syncer.DailyRequestBudget)
		defer client.Stop()
		syncer.New(client, movieUseCase, cfg.Syncer.FetchDescription).Start(ctx)
		log.Printf("syncer: enabled (budget=%d req/day, fetch_description=%v)",
			cfg.Syncer.DailyRequestBudget, cfg.Syncer.FetchDescription)
	}

	watchlistRepo := postgresadapter.NewWatchlistRepository(pool)

	handler := grpcadapter.NewMovieHandler(
		movieUseCase,
		usecase.NewWatchlistUseCase(watchlistRepo),
	)

	grpcServer := grpc.NewServer()
	movieservicev1.RegisterMovieServiceServer(grpcServer, handler)
	movieservicev1.RegisterMovieAdminServiceServer(grpcServer, handler)
	movieservicev1.RegisterWatchlistServiceServer(grpcServer, handler)
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
	if value := os.Getenv("MOVIE_SERVICE_CONFIG_PATH"); value != "" {
		defaultPath = value
	}

	configPath := flag.String("config", defaultPath, "path to YAML config file")
	flag.Parse()

	return *configPath
}
