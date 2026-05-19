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

	"github.com/BigMoneyBigSuccess/cineMate/proto/social/socialv1"
	grpcadapter "github.com/BigMoneyBigSuccess/cineMate/social-service/internal/adapters/grpc"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/adapters/postgres"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/clients"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/config"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/usecase"
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := openPostgres(ctx, cfg.Postgres.URL)
	if err != nil {
		return err
	}
	defer db.Close()

	authClient, err := clients.NewAuthClient(cfg.Auth.Host, cfg.Auth.Port)
	if err != nil {
		return fmt.Errorf("init auth client: %w", err)
	}
	defer authClient.Close()

	uc := usecase.NewSocialUseCase(
		postgres.NewProfileRepository(db),
		postgres.NewFollowRepository(db),
	)

	handler := grpcadapter.NewSocialHandler(uc)

	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(grpcadapter.AuthUnaryInterceptor(authClient)))
	socialv1.RegisterSocialServiceServer(grpcServer, handler)
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

	log.Printf("social service gRPC listening on %s", cfg.GRPC.Addr)
	if err := grpcServer.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve grpc: %w", err)
	}

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
