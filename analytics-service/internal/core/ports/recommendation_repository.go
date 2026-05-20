package ports

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/core/domain"

	"github.com/google/uuid"
)

// RecommendationRepository persists recommendation history so the service can
// analyze past outputs and avoid repeating the same movies.
type RecommendationRepository interface {
	MarkInteraction(ctx context.Context, recommendationID uuid.UUID, interaction domain.InteractionType) error
	SaveRecommendationsBatch(ctx context.Context, recommendations []domain.MovieRecommendation) error
	ListRecommendationsByUser(ctx context.Context, userID uuid.UUID, filter RecommendationHistoryFilter) ([]domain.MovieRecommendation, error)
	ResetRecommendationsByUser(ctx context.Context, userID uuid.UUID) error
}

type RecommendationHistoryFilter struct {
	Limit  int
	Offset int
}
