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

	"database/sql"

	"github.com/BigMoneyBigSuccess/cineMate/proto/auth/authv1"
	grpcadapter "github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/adapters/grpc"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/adapters/postgres"
	"github.com/BigMoneyBigSuccess/cineMate/clients"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/config"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/utils"
	_ "github.com/lib/pq"
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

	if err := utils.LoadJWTSecret(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := openPostgres(ctx, cfg.Postgres.URL)
	if err != nil {
		return err
	}
	defer db.Close()

	socialClient, err := clients.NewSocialClient(cfg.Social.Host, cfg.Social.Port)
	if err != nil {
		return fmt.Errorf("init social client: %w", err)
	}
	defer socialClient.Close()

	repo := postgres.NewUserRepository(db)
	useCase := usecase.NewAuthUseCase(repo, socialClient)
	authHandler := grpcadapter.NewAuthHandler(useCase)

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(grpcadapter.AuthUnaryInterceptor()))
	authv1.RegisterAuthServiceServer(grpcServer, authHandler)
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

	log.Printf("auth service gRPC listening on %s", cfg.GRPC.Addr)
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
