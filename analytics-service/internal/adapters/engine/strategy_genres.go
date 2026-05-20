package engine

import (
	"context"

	"analytics/internal/core/domain"
	"analytics/internal/core/ports"
)

func (e *Engine) candidatesByGenres(ctx context.Context, filter ports.RecommendationFilter) ([]domain.MovieSnapshot, error) {
	return e.movies.ListMovies(ctx, ports.MovieFilter{
		Genres:    filter.Profile.PreferredGenres,
		Limit:     candidateBuffer(filter.Limit),
		SortBy:    "imdb_rating",
		SortOrder: "desc",
	})
}
