package engine

import (
	"context"
	"fmt"
	"time"

	"analytics/internal/core/domain"
	"analytics/internal/core/ports"

	"github.com/google/uuid"
)

// Engine implements ports.RecommendationEngine. It routes to a strategy-specific
// candidate fetch and then applies shared dedup + ranking logic.
type Engine struct {
	movies ports.MovieRepository
}

func New(movies ports.MovieRepository) *Engine {
	return &Engine{movies: movies}
}

func (e *Engine) Recommend(ctx context.Context, filter ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
	var (
		candidates []domain.MovieSnapshot
		err        error
	)

	switch filter.Strategy {
	case domain.StrategyPreferenceProfileBased:
		candidates, err = e.candidatesByProfile(ctx, filter)
	case domain.StrategyGenresBased:
		candidates, err = e.candidatesByGenres(ctx, filter)
	case domain.StrategyActorsBased:
		candidates, err = e.candidatesByActors(ctx, filter)
	case domain.StrategyDirectorsBased:
		candidates, err = e.candidatesByDirectors(ctx, filter)
	case domain.StrategyAIModelBased:
		candidates, err = e.candidatesByAI(ctx, filter)
	default:
		return nil, fmt.Errorf("unknown recommendation strategy: %s", filter.Strategy)
	}

	if err != nil {
		return nil, err
	}

	return e.rankCandidates(candidates, filter), nil
}

// rankCandidates excludes movies the user has already seen (via explicit feedback
// or prior recommendation history) and assembles the final ordered slice.
func (e *Engine) rankCandidates(candidates []domain.MovieSnapshot, filter ports.RecommendationFilter) []domain.MovieRecommendation {
	seen := make(map[uuid.UUID]struct{})
	for _, fb := range filter.Feedback {
		seen[fb.MovieID] = struct{}{}
	}
	for _, r := range filter.RecentRecommendations {
		seen[r.MovieID] = struct{}{}
	}

	sessionID := uuid.New()
	now := time.Now()

	recs := make([]domain.MovieRecommendation, 0, filter.Limit)
	rank := 1
	for _, m := range candidates {
		if _, ok := seen[m.MovieID]; ok {
			continue
		}
		recs = append(recs, domain.MovieRecommendation{
			RecommendationID: uuid.New(),
			SessionID:        sessionID,
			UserID:           filter.Profile.UserID,
			MovieID:          m.MovieID,
			Rank:             rank,
			Strategy:         filter.Strategy,
			GeneratedAt:      now,
			Interaction:      domain.InteractionTypeDismiss,
		})
		rank++
		if len(recs) == filter.Limit {
			break
		}
	}
	return recs
}
