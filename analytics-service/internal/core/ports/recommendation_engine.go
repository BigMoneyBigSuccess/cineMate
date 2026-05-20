package ports

import (
	"context"

	"analytics/internal/core/domain"
)

// RecommendationEngine owns the ranking logic. The use case layer prepares the
// inputs, while the engine decides which candidates deserve the final positions.
type RecommendationEngine interface {
	Recommend(ctx context.Context, filter RecommendationFilter) ([]domain.MovieRecommendation, error)
}

type RecommendationFilter struct {
	Profile               domain.UserPreferenceProfile
	Feedback              []domain.MovieFeedback
	RecentRecommendations []domain.MovieRecommendation
	Strategy              domain.RecommendationStrategy
	Limit                 int
}
