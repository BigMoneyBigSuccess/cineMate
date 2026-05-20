package engine

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/core/ports"
)

// candidatesByAI is a stub for a future AI-powered recommendation.
//
// When a model provider is chosen, replace the body with a call that sends
// aiRequest to the model and parses its movie suggestions back into snapshots.
// The rest of the engine (dedup, ranking, persistence) remains untouched.
func (e *Engine) candidatesByAI(_ context.Context, filter ports.RecommendationFilter) ([]domain.MovieSnapshot, error) {
	_ = buildAIRequest(filter) // TODO: pass to AI provider
	return nil, nil
}

type aiRequest struct {
	PreferredGenres    []domain.Genre
	PreferredActors    []domain.Person
	PreferredDirectors []domain.Person
	AverageRating      float32
	RecentFeedback     []aiFeedbackEntry
}

type aiFeedbackEntry struct {
	MovieID string
	Rating  int32
	Title   *string
	Content *string
}

func buildAIRequest(filter ports.RecommendationFilter) aiRequest {
	p := filter.Profile

	feedback := make([]aiFeedbackEntry, 0, len(filter.Feedback))
	for _, fb := range filter.Feedback {
		feedback = append(feedback, aiFeedbackEntry{
			MovieID: fb.MovieID.String(),
			Rating:  fb.Rating,
			Title:   fb.Title,
			Content: fb.Content,
		})
	}

	return aiRequest{
		PreferredGenres:    p.PreferredGenres,
		PreferredActors:    p.PreferredActors,
		PreferredDirectors: p.PreferredDirectors,
		AverageRating:      p.AverageRating,
		RecentFeedback:     feedback,
	}
}
