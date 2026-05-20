package usecase

import (
	"context"

	"analytics/internal/core/domain"
	"analytics/internal/core/ports"

	"github.com/google/uuid"
)

// recentRecsLimit caps how many past recommendations are fed into the engine
// to suppress duplicates without loading the full history on every call.
const recentRecsLimit = 50

type RecommendationRequest struct {
	UserID   uuid.UUID
	Strategy domain.RecommendationStrategy
	Limit    int
}

func (r RecommendationRequest) validate() error {
	if r.UserID == uuid.Nil || r.Limit < 1 {
		return domain.ErrInvalidRecommendationRequest
	}
	return nil
}

type RecommendationUseCase struct {
	profileRepo  ports.UserProfileRepository
	feedbackRepo ports.FeedbackRepository
	recRepo      ports.RecommendationRepository
	engine       ports.RecommendationEngine
}

func NewRecommendationUseCase(
	profileRepo ports.UserProfileRepository,
	feedbackRepo ports.FeedbackRepository,
	recRepo ports.RecommendationRepository,
	engine ports.RecommendationEngine,
) *RecommendationUseCase {
	return &RecommendationUseCase{
		profileRepo:  profileRepo,
		feedbackRepo: feedbackRepo,
		recRepo:      recRepo,
		engine:       engine,
	}
}

// GenerateRecommendations runs the full recommendation flow:
// load profile + feedback + recent history → engine → persist batch → return.
func (uc *RecommendationUseCase) GenerateRecommendations(ctx context.Context, req RecommendationRequest) ([]domain.MovieRecommendation, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}

	profile, err := uc.profileRepo.GetOrCreateProfileByUserID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	feedback, err := uc.feedbackRepo.ListFeedbackByUser(ctx, req.UserID)
	if err != nil {
		return nil, err
	}

	recentRecs, err := uc.recRepo.ListRecommendationsByUser(ctx, req.UserID, ports.RecommendationHistoryFilter{
		Limit: recentRecsLimit,
	})
	if err != nil {
		return nil, err
	}

	recommendations, err := uc.engine.Recommend(ctx, ports.RecommendationFilter{
		Profile:               profile,
		Feedback:              feedback,
		RecentRecommendations: recentRecs,
		Strategy:              req.Strategy,
		Limit:                 req.Limit,
	})
	if err != nil {
		return nil, err
	}

	if err := uc.recRepo.SaveRecommendationsBatch(ctx, recommendations); err != nil {
		return nil, err
	}

	return recommendations, nil
}

func (uc *RecommendationUseCase) MarkInteraction(ctx context.Context, recommendationID uuid.UUID, interaction domain.InteractionType) error {
	if recommendationID == uuid.Nil {
		return domain.ErrInvalidRecommendationInteraction
	}
	if interaction != domain.InteractionTypeClick && interaction != domain.InteractionTypeDismiss {
		return domain.ErrInvalidRecommendationInteraction
	}
	return uc.recRepo.MarkInteraction(ctx, recommendationID, interaction)
}

func (uc *RecommendationUseCase) GetHistory(ctx context.Context, userID uuid.UUID, filter ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
	if userID == uuid.Nil {
		return nil, domain.ErrInvalidUserReference
	}
	return uc.recRepo.ListRecommendationsByUser(ctx, userID, filter)
}

func (uc *RecommendationUseCase) ResetHistory(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return domain.ErrInvalidUserReference
	}
	return uc.recRepo.ResetRecommendationsByUser(ctx, userID)
}
