package grpc

import (
	"log/slog"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/logger"
	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
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
		grpc.UnaryInterceptor(logger.UnaryServerInterceptor(log)),
	)

	analyticsv1.RegisterFeedbackServiceServer(srv, NewFeedbackHandler(feedbackUC, profileUC))
	analyticsv1.RegisterRecommendationServiceServer(srv, NewRecommendationsHandler(recUC, movies, defaultLimit))

	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(srv, healthSrv)
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	return srv
}
