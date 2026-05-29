package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BigMoneyBigSuccess/cineMate/logger"
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
	log := logger.New("movie-service")
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("movie-service exited with error", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := appconfig.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("config loaded", "summary", cfg.String())

	pool, err := postgresadapter.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("postgres connected")

	redisClient, err := openRedis(ctx, log, cfg.Redis)
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
		syncer.New(client, movieUseCase, log, cfg.Syncer.FetchDescription).Start(ctx)
		log.Info("syncer enabled",
			"budget_req_per_day", cfg.Syncer.DailyRequestBudget,
			"fetch_description", cfg.Syncer.FetchDescription,
		)
	}

	watchlistRepo := postgresadapter.NewWatchlistRepository(pool)

	handler := grpcadapter.NewMovieHandler(
		movieUseCase,
		usecase.NewWatchlistUseCase(watchlistRepo),
	)

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(logger.UnaryServerInterceptor(log)))
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
		log.Info("shutdown signal received")
		shutdownGRPCServer(grpcServer, cfg.ShutdownTimeout)
	}()

	log.Info("movie gRPC server listening", "addr", cfg.GRPC.Addr)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve grpc: %w", err)
	}

	log.Info("movie service stopped")
	return nil
}

func openRedis(ctx context.Context, log *slog.Logger, cfg appconfig.RedisConfig) (*redis.Client, error) {
	if cfg.Addr == "" {
		log.Info("redis disabled, movie cache off")
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
