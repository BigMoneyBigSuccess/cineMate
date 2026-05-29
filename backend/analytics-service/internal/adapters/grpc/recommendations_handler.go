package grpc

import (
	"context"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/usecase"
	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"
	moviev1 "github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type RecommendationsHandler struct {
	analyticsv1.UnimplementedRecommendationServiceServer
	recUC        *usecase.RecommendationUseCase
	movies       ports.MovieRepository
	defaultLimit int
}

func NewRecommendationsHandler(recUC *usecase.RecommendationUseCase, movies ports.MovieRepository, defaultLimit int) *RecommendationsHandler {
	return &RecommendationsHandler{recUC: recUC, movies: movies, defaultLimit: defaultLimit}
}

func (h *RecommendationsHandler) GenerateRecommendations(ctx context.Context, req *analyticsv1.GenerateRecommendationsRequest) (*analyticsv1.GenerateRecommendationsResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	strategy := domain.RecommendationStrategy(req.GetStrategy())
	if strategy == "" {
		strategy = domain.StrategyPreferenceProfileBased
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = h.defaultLimit
	}

	recs, err := h.recUC.GenerateRecommendations(ctx, usecase.RecommendationRequest{
		UserID:   userID,
		Strategy: strategy,
		Limit:    limit,
	})
	if err != nil {
		return nil, domainErr(err)
	}

	protos := make([]*analyticsv1.Recommendation, 0, len(recs))
	for _, r := range recs {
		p, err := h.buildRecommendationProto(ctx, r)
		if err != nil {
			return nil, domainErr(err)
		}
		protos = append(protos, p)
	}
	return &analyticsv1.GenerateRecommendationsResponse{Recommendations: protos}, nil
}

func (h *RecommendationsHandler) MarkInteraction(ctx context.Context, req *analyticsv1.MarkInteractionRequest) (*emptypb.Empty, error) {
	recID, err := uuid.Parse(req.GetRecommendationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid recommendation_id: %v", err)
	}

	interaction := domain.InteractionType(req.GetInteraction())
	if err := h.recUC.MarkInteraction(ctx, recID, interaction); err != nil {
		return nil, domainErr(err)
	}
	return &emptypb.Empty{}, nil
}

func (h *RecommendationsHandler) ResetRecommendationHistory(ctx context.Context, req *analyticsv1.ResetRecommendationHistoryRequest) (*emptypb.Empty, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}
	if err := h.recUC.ResetHistory(ctx, userID); err != nil {
		return nil, domainErr(err)
	}
	return &emptypb.Empty{}, nil
}

func (h *RecommendationsHandler) GetRecommendationHistory(ctx context.Context, req *analyticsv1.GetRecommendationHistoryRequest) (*analyticsv1.GetRecommendationHistoryResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}

	strategy := domain.RecommendationStrategy(req.GetStrategy())
	if _, ok := domain.ValidStrategies[strategy]; !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown strategy %q", req.GetStrategy())
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = h.defaultLimit
	}

	recs, err := h.recUC.GetHistory(ctx, userID, ports.RecommendationHistoryFilter{
		Strategy: strategy,
		Limit:    limit,
	})
	if err != nil {
		return nil, domainErr(err)
	}

	protos := make([]*analyticsv1.Recommendation, 0, len(recs))
	for _, r := range recs {
		p, err := h.buildRecommendationProto(ctx, r)
		if err != nil {
			return nil, domainErr(err)
		}
		protos = append(protos, p)
	}
	return &analyticsv1.GetRecommendationHistoryResponse{Recommendations: protos}, nil
}

func (h *RecommendationsHandler) buildRecommendationProto(ctx context.Context, r domain.MovieRecommendation) (*analyticsv1.Recommendation, error) {
	rec := &analyticsv1.Recommendation{
		RecommendationId: r.RecommendationID.String(),
		Strategy:         string(r.Strategy),
		AiResponse:       r.AIResponse,
		Rank:             int32(r.Rank),
		GeneratedAt:      r.GeneratedAt.Unix(),
	}
	if r.MovieID != nil {
		snap, err := h.movies.GetMovieByID(ctx, *r.MovieID)
		if err != nil {
			return nil, err
		}
		rec.Movie = snapshotToProtoMovie(snap)
	}
	return rec, nil
}

func snapshotToProtoMovie(s *domain.MovieSnapshot) *moviev1.Movie {
	m := &moviev1.Movie{
		MovieId:     s.MovieID.String(),
		Title:       s.Title,
		Description: s.Description,
		Country:     s.Country,
		ReleaseYear: s.ReleaseYear,
		ImdbRating:  s.IMDbRating,
	}
	for _, g := range s.Genres {
		m.Genres = append(m.Genres, &moviev1.Genre{Id: g.ID.String(), Name: g.Name})
	}
	for _, a := range s.Actors {
		m.Actors = append(m.Actors, snapshotPersonToProto(a))
	}
	for _, d := range s.Directors {
		m.Directors = append(m.Directors, snapshotPersonToProto(d))
	}
	return m
}

func snapshotPersonToProto(p domain.Person) *moviev1.Person {
	proto := &moviev1.Person{
		Id:      p.ID.String(),
		Name:    p.Name,
		Surname: p.Surname,
	}
	if p.BirthYear != 0 {
		proto.BirthYear = &p.BirthYear
	}
	return proto
}
