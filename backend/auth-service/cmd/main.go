package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	grpcadapter "github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/adapters/grpc"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/adapters/postgres"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/config"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/utils"
	"github.com/BigMoneyBigSuccess/cineMate/clients"
	"github.com/BigMoneyBigSuccess/cineMate/logger"
	"github.com/BigMoneyBigSuccess/cineMate/proto/auth/authv1"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	log := logger.New("auth-service")
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("auth-service exited with error", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := utils.LoadJWTSecret(); err != nil {
		return fmt.Errorf("load jwt secret: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := openPostgres(ctx, cfg.Postgres.URL)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("postgres connected")

	socialClient, err := clients.NewSocialClient(cfg.Social.Host, cfg.Social.Port)
	if err != nil {
		return fmt.Errorf("init social client: %w", err)
	}
	defer socialClient.Close()
	log.Info("social client connected", "host", cfg.Social.Host, "port", cfg.Social.Port)

	repo := postgres.NewUserRepository(db)
	blacklist := postgres.NewTokenBlacklistRepository(db)
	useCase := usecase.NewAuthUseCase(repo, socialClient, blacklist)
	authHandler := grpcadapter.NewAuthHandler(useCase)

	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		logger.UnaryServerInterceptor(log),
		grpcadapter.AuthUnaryInterceptor(),
	))
	authv1.RegisterAuthServiceServer(grpcServer, authHandler)
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

	log.Info("auth gRPC server listening", "addr", cfg.GRPC.Addr)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve grpc: %w", err)
	}

	log.Info("auth service stopped")
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
	if value := os.Getenv("AUTH_CONFIG_PATH"); value != "" {
		defaultPath = value
	}

	configPath := flag.String("config", defaultPath, "path to YAML config file")
	flag.Parse()

	return *configPath
}
