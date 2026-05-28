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

	grpcadapter "github.com/BigMoneyBigSuccess/cineMate/social-service/internal/adapters/grpc"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/adapters/postgres"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/config"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/clients"
	"github.com/BigMoneyBigSuccess/cineMate/logger"
	"github.com/BigMoneyBigSuccess/cineMate/proto/social/socialv1"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	log := logger.New("social-service")
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("social-service exited with error", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := openPostgres(ctx, cfg.Postgres.URL)
	if err != nil {
		return err
	}
	defer db.Close()
	log.Info("postgres connected")

	authClient, err := clients.NewAuthClient(cfg.Auth.Host, cfg.Auth.Port)
	if err != nil {
		return fmt.Errorf("init auth client: %w", err)
	}
	defer authClient.Close()
	log.Info("auth client connected", "host", cfg.Auth.Host, "port", cfg.Auth.Port)

	uc := usecase.NewSocialUseCase(
		postgres.NewProfileRepository(db),
		postgres.NewFollowRepository(db),
	)

	handler := grpcadapter.NewSocialHandler(uc)

	grpcServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		logger.UnaryServerInterceptor(log),
		grpcadapter.AuthUnaryInterceptor(authClient),
	))
	socialv1.RegisterSocialServiceServer(grpcServer, handler)
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

	log.Info("social gRPC server listening", "addr", cfg.GRPC.Addr)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve grpc: %w", err)
	}

	log.Info("social service stopped")
	return nil
}

func openPostgres(ctx context.Context, url string) (*sql.DB, error) {
	db, err := sql.Open("postgres", url)
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
	if v := os.Getenv("SOCIAL_CONFIG_PATH"); v != "" {
		defaultPath = v
	}
	configPath := flag.String("config", defaultPath, "path to YAML config file")
	flag.Parse()
	return *configPath
}
