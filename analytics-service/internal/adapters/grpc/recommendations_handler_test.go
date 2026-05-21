package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/usecase"
	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- mock port implementations reused within this package ---

type recHandlerMockProfileRepo struct {
	getOrCreateFn func(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error)
}

func (m *recHandlerMockProfileRepo) UpsertProfile(_ context.Context, _ domain.UserPreferenceProfile) error {
	return nil
}
func (m *recHandlerMockProfileRepo) RemoveProfile(_ context.Context, _ uuid.UUID) error { return nil }
func (m *recHandlerMockProfileRepo) GetOrCreateProfileByUserID(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error) {
	if m.getOrCreateFn != nil {
		return m.getOrCreateFn(ctx, userID)
	}
	return domain.NewEmptyUserPreferenceProfile(userID), nil
}

type recHandlerMockFeedbackRepo struct {
	listFn func(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error)
}

func (m *recHandlerMockFeedbackRepo) UpsertFeedback(_ context.Context, _ domain.MovieFeedback) error {
	return nil
}
func (m *recHandlerMockFeedbackRepo) RemoveFeedback(_ context.Context, _ uuid.UUID) error {
	return nil
}
func (m *recHandlerMockFeedbackRepo) ListFeedbackByUser(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error) {
	if m.listFn != nil {
		return m.listFn(ctx, userID)
	}
	return nil, nil
}
func (m *recHandlerMockFeedbackRepo) GetFeedbackByID(_ context.Context, _ uuid.UUID) (domain.MovieFeedback, error) {
	return domain.MovieFeedback{}, nil
}

type recHandlerMockRecRepo struct {
	markFn      func(ctx context.Context, id uuid.UUID, interaction domain.InteractionType) error
	saveBatchFn func(ctx context.Context, recs []domain.MovieRecommendation) error
	listFn      func(ctx context.Context, userID uuid.UUID, f ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error)
	resetFn     func(ctx context.Context, userID uuid.UUID) error
}

func (m *recHandlerMockRecRepo) MarkInteraction(ctx context.Context, id uuid.UUID, interaction domain.InteractionType) error {
	if m.markFn != nil {
		return m.markFn(ctx, id, interaction)
	}
	return nil
}
func (m *recHandlerMockRecRepo) SaveRecommendationsBatch(ctx context.Context, recs []domain.MovieRecommendation) error {
	if m.saveBatchFn != nil {
		return m.saveBatchFn(ctx, recs)
	}
	return nil
}
func (m *recHandlerMockRecRepo) ListRecommendationsByUser(ctx context.Context, userID uuid.UUID, f ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
	if m.listFn != nil {
		return m.listFn(ctx, userID, f)
	}
	return nil, nil
}
func (m *recHandlerMockRecRepo) ResetRecommendationsByUser(ctx context.Context, userID uuid.UUID) error {
	if m.resetFn != nil {
		return m.resetFn(ctx, userID)
	}
	return nil
}

type recHandlerMockEngine struct {
	recommendFn func(ctx context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error)
}

func (m *recHandlerMockEngine) Recommend(ctx context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
	if m.recommendFn != nil {
		return m.recommendFn(ctx, f)
	}
	return nil, nil
}

type recHandlerMockMovieRepo struct {
	getByIDFn func(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error)
}

func (m *recHandlerMockMovieRepo) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return &domain.MovieSnapshot{MovieID: id, Title: "stub"}, nil
}
func (m *recHandlerMockMovieRepo) ListMovies(_ context.Context, _ ports.MovieFilter) ([]domain.MovieSnapshot, error) {
	return nil, nil
}

// newRecHandler builds a RecommendationsHandler with all repos/engine injectable.
func newRecHandler(
	profileRepo ports.UserProfileRepository,
	feedbackRepo ports.FeedbackRepository,
	recRepo ports.RecommendationRepository,
	engine ports.RecommendationEngine,
	movies ports.MovieRepository,
	defaultLimit int,
) *RecommendationsHandler {
	uc := usecase.NewRecommendationUseCase(profileRepo, feedbackRepo, recRepo, engine)
	return NewRecommendationsHandler(uc, movies, defaultLimit)
}

func defaultRecHandler() *RecommendationsHandler {
	return newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{},
		&recHandlerMockMovieRepo{},
		10,
	)
}

// --- GenerateRecommendations ---

func TestGenerateRecommendationsHandler_InvalidUserID_ReturnsInvalidArgument(t *testing.T) {
	h := defaultRecHandler()
	_, err := h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId: "not-a-uuid",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestGenerateRecommendationsHandler_EmptyStrategy_DefaultsToPreferenceProfile(t *testing.T) {
	var capturedStrategy domain.RecommendationStrategy
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{
			recommendFn: func(_ context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
				capturedStrategy = f.Strategy
				return nil, nil
			},
		},
		&recHandlerMockMovieRepo{},
		10,
	)

	_, err := h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId:   uuid.New().String(),
		Strategy: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedStrategy != domain.StrategyPreferenceProfileBased {
		t.Errorf("expected preference_profile_based, got %q", capturedStrategy)
	}
}

func TestGenerateRecommendationsHandler_ZeroLimit_UsesDefaultLimit(t *testing.T) {
	var capturedLimit int
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{
			recommendFn: func(_ context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
				capturedLimit = f.Limit
				return nil, nil
			},
		},
		&recHandlerMockMovieRepo{},
		15,
	)

	_, _ = h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId: uuid.New().String(),
		Limit:  0,
	})
	if capturedLimit != 15 {
		t.Errorf("expected default limit 15, got %d", capturedLimit)
	}
}

func TestGenerateRecommendationsHandler_NegativeLimit_UsesDefaultLimit(t *testing.T) {
	var capturedLimit int
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{
			recommendFn: func(_ context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
				capturedLimit = f.Limit
				return nil, nil
			},
		},
		&recHandlerMockMovieRepo{},
		10,
	)
	_, _ = h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId: uuid.New().String(),
		Limit:  -5,
	})
	if capturedLimit != 10 {
		t.Errorf("expected default limit 10, got %d", capturedLimit)
	}
}

func TestGenerateRecommendationsHandler_ExplicitLimit_ForwardedToEngine(t *testing.T) {
	var capturedLimit int
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{
			recommendFn: func(_ context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
				capturedLimit = f.Limit
				return nil, nil
			},
		},
		&recHandlerMockMovieRepo{},
		10,
	)
	_, _ = h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId: uuid.New().String(),
		Limit:  7,
	})
	if capturedLimit != 7 {
		t.Errorf("expected limit 7, got %d", capturedLimit)
	}
}

func TestGenerateRecommendationsHandler_HappyPath_ReturnsProtoRecs(t *testing.T) {
	userID := uuid.New()
	movieID := uuid.New()
	recID := uuid.New()
	sessionID := uuid.New()
	now := time.Now()

	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{
			recommendFn: func(_ context.Context, _ ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
				return []domain.MovieRecommendation{{
					RecommendationID: recID,
					SessionID:        sessionID,
					UserID:           userID,
					MovieID:          &movieID,
					Rank:             1,
					Strategy:         domain.StrategyGenresBased,
					GeneratedAt:      now,
					Interaction:      domain.InteractionTypeDismiss,
				}}, nil
			},
		},
		&recHandlerMockMovieRepo{
			getByIDFn: func(_ context.Context, id uuid.UUID) (*domain.MovieSnapshot, error) {
				return &domain.MovieSnapshot{MovieID: id, Title: "Test Movie"}, nil
			},
		},
		10,
	)

	resp, err := h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId:   userID.String(),
		Strategy: string(domain.StrategyGenresBased),
		Limit:    5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Recommendations) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(resp.Recommendations))
	}

	r := resp.Recommendations[0]
	if r.RecommendationId != recID.String() {
		t.Errorf("recommendation_id mismatch")
	}
	if r.Movie == nil {
		t.Fatal("expected movie to be set")
	}
	if r.Movie.MovieId != movieID.String() {
		t.Errorf("movie_id mismatch")
	}
	if r.Movie.Title != "Test Movie" {
		t.Errorf("movie title mismatch")
	}
	if r.Rank != 1 {
		t.Errorf("rank mismatch: expected 1, got %d", r.Rank)
	}
	if r.Strategy != string(domain.StrategyGenresBased) {
		t.Errorf("strategy mismatch: expected genres_based, got %q", r.Strategy)
	}
	if r.GeneratedAt != now.Unix() {
		t.Errorf("generated_at mismatch")
	}
}

func TestGenerateRecommendationsHandler_UseCaseError_ReturnsGRPCError(t *testing.T) {
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{},
		&recHandlerMockEngine{
			recommendFn: func(_ context.Context, _ ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
				return nil, errors.New("engine failure")
			},
		},
		&recHandlerMockMovieRepo{},
		10,
	)

	_, err := h.GenerateRecommendations(context.Background(), &analyticsv1.GenerateRecommendationsRequest{
		UserId: uuid.New().String(),
		Limit:  5,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	assertGRPCCode(t, err, codes.Internal)
}

// --- MarkInteraction ---

func TestMarkInteractionHandler_InvalidRecommendationID_ReturnsInvalidArgument(t *testing.T) {
	h := defaultRecHandler()
	_, err := h.MarkInteraction(context.Background(), &analyticsv1.MarkInteractionRequest{
		RecommendationId: "bad-uuid",
		Interaction:      "click",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestMarkInteractionHandler_ValidClick_CallsRepo(t *testing.T) {
	recID := uuid.New()
	var capturedID uuid.UUID
	var capturedInteraction domain.InteractionType

	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{markFn: func(_ context.Context, id uuid.UUID, interaction domain.InteractionType) error {
			capturedID = id
			capturedInteraction = interaction
			return nil
		}},
		&recHandlerMockEngine{},
		&recHandlerMockMovieRepo{},
		10,
	)

	_, err := h.MarkInteraction(context.Background(), &analyticsv1.MarkInteractionRequest{
		RecommendationId: recID.String(),
		Interaction:      string(domain.InteractionTypeClick),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedID != recID {
		t.Error("recommendation ID should be forwarded")
	}
	if capturedInteraction != domain.InteractionTypeClick {
		t.Errorf("expected click, got %q", capturedInteraction)
	}
}

func TestMarkInteractionHandler_InvalidInteractionType_ReturnsInvalidArgument(t *testing.T) {
	h := defaultRecHandler()
	_, err := h.MarkInteraction(context.Background(), &analyticsv1.MarkInteractionRequest{
		RecommendationId: uuid.New().String(),
		Interaction:      "view",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

// --- ResetRecommendationHistory ---

func TestResetRecommendationHistoryHandler_InvalidUserID_ReturnsInvalidArgument(t *testing.T) {
	h := defaultRecHandler()
	_, err := h.ResetRecommendationHistory(context.Background(), &analyticsv1.ResetRecommendationHistoryRequest{
		UserId: "bad-id",
	})
	assertGRPCCode(t, err, codes.InvalidArgument)
}

func TestResetRecommendationHistoryHandler_ValidUserID_CallsRepo(t *testing.T) {
	resetCalled := false
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{resetFn: func(_ context.Context, _ uuid.UUID) error {
			resetCalled = true
			return nil
		}},
		&recHandlerMockEngine{},
		&recHandlerMockMovieRepo{},
		10,
	)

	_, err := h.ResetRecommendationHistory(context.Background(), &analyticsv1.ResetRecommendationHistoryRequest{
		UserId: uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resetCalled {
		t.Error("repo reset should have been called")
	}
}

func TestResetRecommendationHistoryHandler_RepoError_ReturnsGRPCError(t *testing.T) {
	h := newRecHandler(
		&recHandlerMockProfileRepo{},
		&recHandlerMockFeedbackRepo{},
		&recHandlerMockRecRepo{resetFn: func(_ context.Context, _ uuid.UUID) error {
			return errors.New("reset failed")
		}},
		&recHandlerMockEngine{},
		&recHandlerMockMovieRepo{},
		10,
	)

	_, err := h.ResetRecommendationHistory(context.Background(), &analyticsv1.ResetRecommendationHistoryRequest{
		UserId: uuid.New().String(),
	})
	if err == nil {
		t.Fatal("expected error")
	}
	assertGRPCCode(t, err, codes.Internal)
}

// --- helpers ---

func assertGRPCCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected gRPC error with code %s, got nil", expected)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got: %v", err)
	}
	if st.Code() != expected {
		t.Errorf("expected gRPC code %s, got %s", expected, st.Code())
	}
}
