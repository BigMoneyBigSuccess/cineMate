package grpc

import (
	"context"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/usecase"
	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func NewServer(
	log *slog.Logger,
	feedbackUC *usecase.FeedbackUseCase,
	profileUC *usecase.UserProfileUseCase,
	recUC *usecase.RecommendationUseCase,
	movies ports.MovieRepository,
	defaultLimit int,
) *grpc.Server {
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			recoveryInterceptor(log),
			loggingInterceptor(log),
		),
	)

	analyticsv1.RegisterFeedbackServiceServer(srv, NewFeedbackHandler(feedbackUC, profileUC))
	analyticsv1.RegisterRecommendationServiceServer(srv, NewRecommendationsHandler(recUC, movies, defaultLimit))

	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(srv, healthSrv)
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	return srv
}

func recoveryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic recovered", "method", info.FullMethod, "panic", r, "stack", string(debug.Stack()))
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}

func loggingInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}
		log.Info("grpc",
			"method", info.FullMethod,
			"code", code,
			"duration_ms", time.Since(start).Milliseconds(),
			"error", err,
		)
		return resp, err
	}
}
