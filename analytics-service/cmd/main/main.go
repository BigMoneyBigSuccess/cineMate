package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/adapters/engine"
	grpcadapter "github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/adapters/grpc"
	movieservice "github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/adapters/movie-service"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/adapters/postgres"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/config"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/clients"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(os.Getenv("ANALYTICS_CONFIG_PATH"))
	if err != nil {
		log.Error("load config", "error", err)
		os.Exit(1)
	}
	log.Info("config loaded", "summary", cfg.String())

	ctx := context.Background()

	db, err := postgres.NewPool(ctx, cfg.Postgres)
	if err != nil {
		log.Error("connect postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	log.Info("postgres connected")

	host, portStr, err := net.SplitHostPort(cfg.MovieCollection.Addr)
	if err != nil {
		log.Error("parse movie collection addr", "addr", cfg.MovieCollection.Addr, "error", err)
		os.Exit(1)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Error("parse movie collection port", "port", portStr, "error", err)
		os.Exit(1)
	}
	movieClient, err := clients.NewMovieClient(host, port)
	if err != nil {
		log.Error("connect movie-collection", "error", err)
		os.Exit(1)
	}
	defer movieClient.Close()
	log.Info("movie-collection connected", "addr", cfg.MovieCollection.Addr)

	feedbackRepo := postgres.NewFeedbackRepository(db)
	profileRepo := postgres.NewUserProfileRepository(db)
	recRepo := postgres.NewRecommendationRepository(db)

	catalog := movieservice.NewMovieServiceClient(movieClient, cfg.MovieCollection.Timeout)
	recEngine := engine.New(catalog)

	feedbackUC := usecase.NewFeedbackUseCase(feedbackRepo)
	profileUC := usecase.NewUserProfileUseCase(profileRepo, feedbackRepo, catalog)
	recUC := usecase.NewRecommendationUseCase(profileRepo, feedbackRepo, recRepo, recEngine)

	srv := grpcadapter.NewServer(log, feedbackUC, profileUC, recUC, catalog, cfg.Recommendation.DefaultLimit)

	lis, err := net.Listen("tcp", cfg.GRPC.Addr)
	if err != nil {
		log.Error("listen", "addr", cfg.GRPC.Addr, "error", err)
		os.Exit(1)
	}

	log.Info("analytics gRPC server starting", "addr", cfg.GRPC.Addr)
	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Error("server exited", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		log.Info("shutdown complete")
	case <-shutdownCtx.Done():
		log.Warn("shutdown timeout exceeded, forcing stop")
		srv.Stop()
	}
}
