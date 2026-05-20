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

	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/adapters/engine"
	moviecollection "github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/adapters/movie-collection-service"
	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/adapters/postgres"
	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/config"
	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/core/usecase"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("init postgres: %w", err)
	}
	defer pool.Close()

	movieConn, err := moviecollection.NewConn(cfg.MovieCollection)
	if err != nil {
		return fmt.Errorf("init movie collection client: %w", err)
	}
	defer movieConn.Close()

	movieClient := moviecollection.New(movieConn, cfg.MovieCollection.Timeout)
	feedbackRepo := postgres.NewFeedbackRepository(pool)
	recRepo := postgres.NewRecommendationRepository(pool)
	profileRepo := postgres.NewUserProfileRepository(pool)
	recommendationEngine := engine.New(movieClient)

	_ = usecase.NewRecommendationUseCase(profileRepo, feedbackRepo, recRepo, recommendationEngine)
	_ = usecase.NewFeedbackUseCase(feedbackRepo)
	_ = usecase.NewUserProfileUseCase(profileRepo, feedbackRepo, movieClient)

	grpcServer := grpc.NewServer()
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

	log.Printf("analytics service gRPC listening on %s", cfg.GRPC.Addr)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve grpc: %w", err)
	}

	return nil
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
	defaultPath := config.DefaultPath
	if v := os.Getenv("ANALYTICS_CONFIG_PATH"); v != "" {
		defaultPath = v
	}
	configPath := flag.String("config", defaultPath, "path to YAML config file")
	flag.Parse()
	return *configPath
}
