package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
)

// --- mock port implementations ---

type mockProfileRepo struct {
	upsertFn      func(ctx context.Context, p domain.UserPreferenceProfile) error
	removeFn      func(ctx context.Context, userID uuid.UUID) error
	getOrCreateFn func(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error)
}

func (m *mockProfileRepo) UpsertProfile(ctx context.Context, p domain.UserPreferenceProfile) error {
	if m.upsertFn != nil {
		return m.upsertFn(ctx, p)
	}
	return nil
}
func (m *mockProfileRepo) RemoveProfile(ctx context.Context, userID uuid.UUID) error {
	if m.removeFn != nil {
		return m.removeFn(ctx, userID)
	}
	return nil
}
func (m *mockProfileRepo) GetOrCreateProfileByUserID(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error) {
	if m.getOrCreateFn != nil {
		return m.getOrCreateFn(ctx, userID)
	}
	return domain.NewEmptyUserPreferenceProfile(userID), nil
}

type mockFeedbackRepo struct {
	upsertFn    func(ctx context.Context, fb domain.MovieFeedback) error
	removeFn    func(ctx context.Context, feedbackID uuid.UUID) error
	listFn      func(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error)
	getByIDFn   func(ctx context.Context, feedbackID uuid.UUID) (domain.MovieFeedback, error)
}

func (m *mockFeedbackRepo) UpsertFeedback(ctx context.Context, fb domain.MovieFeedback) error {
	if m.upsertFn != nil {
		return m.upsertFn(ctx, fb)
	}
	return nil
}
func (m *mockFeedbackRepo) RemoveFeedback(ctx context.Context, id uuid.UUID) error {
	if m.removeFn != nil {
		return m.removeFn(ctx, id)
	}
	return nil
}
func (m *mockFeedbackRepo) ListFeedbackByUser(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error) {
	if m.listFn != nil {
		return m.listFn(ctx, userID)
	}
	return nil, nil
}
func (m *mockFeedbackRepo) GetFeedbackByID(ctx context.Context, id uuid.UUID) (domain.MovieFeedback, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return domain.MovieFeedback{}, nil
}

type mockRecRepo struct {
	markFn      func(ctx context.Context, id uuid.UUID, interaction domain.InteractionType) error
	saveBatchFn func(ctx context.Context, recs []domain.MovieRecommendation) error
	listFn      func(ctx context.Context, userID uuid.UUID, f ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error)
	resetFn     func(ctx context.Context, userID uuid.UUID) error
}

func (m *mockRecRepo) MarkInteraction(ctx context.Context, id uuid.UUID, interaction domain.InteractionType) error {
	if m.markFn != nil {
		return m.markFn(ctx, id, interaction)
	}
	return nil
}
func (m *mockRecRepo) SaveRecommendationsBatch(ctx context.Context, recs []domain.MovieRecommendation) error {
	if m.saveBatchFn != nil {
		return m.saveBatchFn(ctx, recs)
	}
	return nil
}
func (m *mockRecRepo) ListRecommendationsByUser(ctx context.Context, userID uuid.UUID, f ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
	if m.listFn != nil {
		return m.listFn(ctx, userID, f)
	}
	return nil, nil
}
func (m *mockRecRepo) ResetRecommendationsByUser(ctx context.Context, userID uuid.UUID) error {
	if m.resetFn != nil {
		return m.resetFn(ctx, userID)
	}
	return nil
}

type mockRecEngine struct {
	recommendFn func(ctx context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error)
}

func (m *mockRecEngine) Recommend(ctx context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
	if m.recommendFn != nil {
		return m.recommendFn(ctx, f)
	}
	return nil, nil
}

// --- GenerateRecommendations ---

func TestGenerateRecommendations_NilUserID_ReturnsValidationError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.Nil,
		Limit:  5,
	})
	if !errors.Is(err, domain.ErrInvalidRecommendationRequest) {
		t.Errorf("expected ErrInvalidRecommendationRequest, got %v", err)
	}
}

func TestGenerateRecommendations_ZeroLimit_ReturnsValidationError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.New(),
		Limit:  0,
	})
	if !errors.Is(err, domain.ErrInvalidRecommendationRequest) {
		t.Errorf("expected ErrInvalidRecommendationRequest, got %v", err)
	}
}

func TestGenerateRecommendations_NegativeLimit_ReturnsValidationError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.New(),
		Limit:  -1,
	})
	if !errors.Is(err, domain.ErrInvalidRecommendationRequest) {
		t.Errorf("expected ErrInvalidRecommendationRequest, got %v", err)
	}
}

func TestGenerateRecommendations_ProfileRepoError_PropagatesError(t *testing.T) {
	dbErr := errors.New("db unavailable")
	uc := NewRecommendationUseCase(
		&mockProfileRepo{getOrCreateFn: func(_ context.Context, _ uuid.UUID) (domain.UserPreferenceProfile, error) {
			return domain.UserPreferenceProfile{}, dbErr
		}},
		&mockFeedbackRepo{},
		&mockRecRepo{},
		&mockRecEngine{},
	)
	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.New(), Limit: 5,
	})
	if !errors.Is(err, dbErr) {
		t.Errorf("expected dbErr, got %v", err)
	}
}

func TestGenerateRecommendations_FeedbackRepoError_PropagatesError(t *testing.T) {
	dbErr := errors.New("feedback db down")
	uc := NewRecommendationUseCase(
		&mockProfileRepo{},
		&mockFeedbackRepo{listFn: func(_ context.Context, _ uuid.UUID) ([]domain.MovieFeedback, error) {
			return nil, dbErr
		}},
		&mockRecRepo{},
		&mockRecEngine{},
	)
	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.New(), Limit: 5,
	})
	if !errors.Is(err, dbErr) {
		t.Errorf("expected dbErr, got %v", err)
	}
}

func TestGenerateRecommendations_RecentHistoryFetchedWithCorrectLimit(t *testing.T) {
	var capturedHistFilter ports.RecommendationHistoryFilter
	uc := NewRecommendationUseCase(
		&mockProfileRepo{},
		&mockFeedbackRepo{},
		&mockRecRepo{listFn: func(_ context.Context, _ uuid.UUID, f ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
			capturedHistFilter = f
			return nil, nil
		}},
		&mockRecEngine{},
	)
	_, _ = uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.New(), Limit: 5,
	})
	if capturedHistFilter.Limit != recentRecsLimit {
		t.Errorf("expected recent recs limit %d, got %d", recentRecsLimit, capturedHistFilter.Limit)
	}
}

func TestGenerateRecommendations_PassesProfileFeedbackAndStrategyToEngine(t *testing.T) {
	userID := uuid.New()
	genreID := uuid.New()
	movieID := uuid.New()

	profile := domain.UserPreferenceProfile{
		UserID:          userID,
		PreferredGenres: []domain.Genre{{ID: genreID, Name: "Action"}},
	}
	feedback := []domain.MovieFeedback{
		{FeedbackID: uuid.New(), UserID: userID, MovieID: movieID, Rating: 8},
	}

	var capturedFilter ports.RecommendationFilter
	uc := NewRecommendationUseCase(
		&mockProfileRepo{getOrCreateFn: func(_ context.Context, _ uuid.UUID) (domain.UserPreferenceProfile, error) {
			return profile, nil
		}},
		&mockFeedbackRepo{listFn: func(_ context.Context, _ uuid.UUID) ([]domain.MovieFeedback, error) {
			return feedback, nil
		}},
		&mockRecRepo{},
		&mockRecEngine{recommendFn: func(_ context.Context, f ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
			capturedFilter = f
			return nil, nil
		}},
	)

	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID:   userID,
		Strategy: domain.StrategyGenresBased,
		Limit:    5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedFilter.Profile.UserID != userID {
		t.Error("engine should receive the user's profile")
	}
	if len(capturedFilter.Profile.PreferredGenres) != 1 || capturedFilter.Profile.PreferredGenres[0].ID != genreID {
		t.Error("engine should receive preferred genres from profile")
	}
	if len(capturedFilter.Feedback) != 1 || capturedFilter.Feedback[0].MovieID != movieID {
		t.Error("engine should receive user feedback")
	}
	if capturedFilter.Strategy != domain.StrategyGenresBased {
		t.Errorf("engine strategy mismatch: expected genres_based, got %q", capturedFilter.Strategy)
	}
	if capturedFilter.Limit != 5 {
		t.Errorf("engine limit mismatch: expected 5, got %d", capturedFilter.Limit)
	}
}

func TestGenerateRecommendations_HappyPath_PersistsAndReturnsRecs(t *testing.T) {
	userID := uuid.New()
	movieID := uuid.New()
	engineRecs := []domain.MovieRecommendation{
		{
			RecommendationID: uuid.New(),
			SessionID:        uuid.New(),
			UserID:           userID,
			MovieID:          &movieID,
			Rank:             1,
			Strategy:         domain.StrategyGenresBased,
			GeneratedAt:      time.Now(),
			Interaction:      domain.InteractionTypeDismiss,
		},
	}

	var savedRecs []domain.MovieRecommendation
	uc := NewRecommendationUseCase(
		&mockProfileRepo{},
		&mockFeedbackRepo{},
		&mockRecRepo{saveBatchFn: func(_ context.Context, recs []domain.MovieRecommendation) error {
			savedRecs = recs
			return nil
		}},
		&mockRecEngine{recommendFn: func(_ context.Context, _ ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
			return engineRecs, nil
		}},
	)

	recs, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: userID, Strategy: domain.StrategyGenresBased, Limit: 5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	if savedRecs == nil {
		t.Error("batch save should have been called")
	}
	if recs[0].UserID != userID {
		t.Error("returned rec should belong to the user")
	}
}

func TestGenerateRecommendations_SaveBatchError_PropagatesError(t *testing.T) {
	saveErr := errors.New("save failed")
	uc := NewRecommendationUseCase(
		&mockProfileRepo{},
		&mockFeedbackRepo{},
		&mockRecRepo{saveBatchFn: func(_ context.Context, _ []domain.MovieRecommendation) error {
			return saveErr
		}},
		&mockRecEngine{recommendFn: func(_ context.Context, _ ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
			mid := uuid.New()
			return []domain.MovieRecommendation{{
				RecommendationID: uuid.New(), SessionID: uuid.New(),
				UserID: uuid.New(), MovieID: &mid, Rank: 1,
				Strategy:    domain.StrategyGenresBased,
				GeneratedAt: time.Now(), Interaction: domain.InteractionTypeDismiss,
			}}, nil
		}},
	)
	_, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID: uuid.New(), Limit: 5,
	})
	if !errors.Is(err, saveErr) {
		t.Errorf("expected saveErr, got %v", err)
	}
}

// --- MarkInteraction ---

func TestMarkInteraction_NilRecommendationID_ReturnsError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	err := uc.MarkInteraction(context.Background(), uuid.Nil, domain.InteractionTypeClick)
	if !errors.Is(err, domain.ErrInvalidRecommendationInteraction) {
		t.Errorf("expected ErrInvalidRecommendationInteraction, got %v", err)
	}
}

func TestMarkInteraction_InvalidInteractionType_ReturnsError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	err := uc.MarkInteraction(context.Background(), uuid.New(), domain.InteractionType("view"))
	if !errors.Is(err, domain.ErrInvalidRecommendationInteraction) {
		t.Errorf("expected ErrInvalidRecommendationInteraction, got %v", err)
	}
}

func TestMarkInteraction_Click_ForwardedToRepo(t *testing.T) {
	recID := uuid.New()
	var capturedID uuid.UUID
	var capturedInteraction domain.InteractionType

	uc := NewRecommendationUseCase(
		&mockProfileRepo{}, &mockFeedbackRepo{},
		&mockRecRepo{markFn: func(_ context.Context, id uuid.UUID, interaction domain.InteractionType) error {
			capturedID = id
			capturedInteraction = interaction
			return nil
		}},
		&mockRecEngine{},
	)

	err := uc.MarkInteraction(context.Background(), recID, domain.InteractionTypeClick)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedID != recID {
		t.Error("recommendation ID should be forwarded to repo")
	}
	if capturedInteraction != domain.InteractionTypeClick {
		t.Errorf("interaction should be click, got %q", capturedInteraction)
	}
}

func TestMarkInteraction_Dismiss_ForwardedToRepo(t *testing.T) {
	var capturedInteraction domain.InteractionType
	uc := NewRecommendationUseCase(
		&mockProfileRepo{}, &mockFeedbackRepo{},
		&mockRecRepo{markFn: func(_ context.Context, _ uuid.UUID, interaction domain.InteractionType) error {
			capturedInteraction = interaction
			return nil
		}},
		&mockRecEngine{},
	)

	_ = uc.MarkInteraction(context.Background(), uuid.New(), domain.InteractionTypeDismiss)
	if capturedInteraction != domain.InteractionTypeDismiss {
		t.Errorf("interaction should be dismiss, got %q", capturedInteraction)
	}
}

// --- GetHistory ---

func TestGetHistory_NilUserID_ReturnsError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	_, err := uc.GetHistory(context.Background(), uuid.Nil, ports.RecommendationHistoryFilter{})
	if !errors.Is(err, domain.ErrInvalidUserReference) {
		t.Errorf("expected ErrInvalidUserReference, got %v", err)
	}
}

func TestGetHistory_ForwardsPaginationToRepo(t *testing.T) {
	var capturedFilter ports.RecommendationHistoryFilter
	uc := NewRecommendationUseCase(
		&mockProfileRepo{}, &mockFeedbackRepo{},
		&mockRecRepo{listFn: func(_ context.Context, _ uuid.UUID, f ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
			capturedFilter = f
			return nil, nil
		}},
		&mockRecEngine{},
	)

	filter := ports.RecommendationHistoryFilter{Limit: 20, Offset: 40}
	_, _ = uc.GetHistory(context.Background(), uuid.New(), filter)

	if capturedFilter.Limit != 20 || capturedFilter.Offset != 40 {
		t.Errorf("pagination not forwarded: got limit=%d offset=%d", capturedFilter.Limit, capturedFilter.Offset)
	}
}

func TestGetHistory_RepoError_Propagates(t *testing.T) {
	repoErr := errors.New("history repo error")
	uc := NewRecommendationUseCase(
		&mockProfileRepo{}, &mockFeedbackRepo{},
		&mockRecRepo{listFn: func(_ context.Context, _ uuid.UUID, _ ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
			return nil, repoErr
		}},
		&mockRecEngine{},
	)
	_, err := uc.GetHistory(context.Background(), uuid.New(), ports.RecommendationHistoryFilter{})
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repoErr, got %v", err)
	}
}

// --- ResetHistory ---

func TestResetHistory_NilUserID_ReturnsError(t *testing.T) {
	uc := NewRecommendationUseCase(&mockProfileRepo{}, &mockFeedbackRepo{}, &mockRecRepo{}, &mockRecEngine{})
	err := uc.ResetHistory(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidUserReference) {
		t.Errorf("expected ErrInvalidUserReference, got %v", err)
	}
}

func TestResetHistory_ValidUserID_CallsRepo(t *testing.T) {
	resetCalled := false
	var capturedUserID uuid.UUID
	userID := uuid.New()

	uc := NewRecommendationUseCase(
		&mockProfileRepo{}, &mockFeedbackRepo{},
		&mockRecRepo{resetFn: func(_ context.Context, uid uuid.UUID) error {
			resetCalled = true
			capturedUserID = uid
			return nil
		}},
		&mockRecEngine{},
	)

	err := uc.ResetHistory(context.Background(), userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resetCalled {
		t.Error("repo reset should have been called")
	}
	if capturedUserID != userID {
		t.Error("user ID should be forwarded to repo")
	}
}

func TestResetHistory_RepoError_Propagates(t *testing.T) {
	repoErr := errors.New("reset failed")
	uc := NewRecommendationUseCase(
		&mockProfileRepo{}, &mockFeedbackRepo{},
		&mockRecRepo{resetFn: func(_ context.Context, _ uuid.UUID) error { return repoErr }},
		&mockRecEngine{},
	)
	err := uc.ResetHistory(context.Background(), uuid.New())
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repoErr, got %v", err)
	}
}
