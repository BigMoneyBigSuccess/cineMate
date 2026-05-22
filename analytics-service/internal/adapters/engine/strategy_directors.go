package engine

import (
	"context"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
)

func (e *Engine) candidatesByDirectors(ctx context.Context, filter ports.RecommendationFilter) ([]domain.MovieSnapshot, error) {
	return e.movies.ListMovies(ctx, ports.MovieFilter{
		Directors: filter.Profile.PreferredDirectors,
		Limit:     candidateBuffer(filter.Limit),
		SortBy:    "imdb_rating",
		SortOrder: "desc",
	})
}
