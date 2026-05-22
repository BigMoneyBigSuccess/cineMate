package ports

import (
	"context"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"

	"github.com/google/uuid"
)

// MovieCatalog is the outbound boundary to movie_collection. It allows
// analytics to fetch candidate movies without depending on another service's
// internal implementation details.
type MovieRepository interface {
	GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error)
	ListMovies(ctx context.Context, filter MovieFilter) ([]domain.MovieSnapshot, error)
}

type MovieFilter struct {
	Query           string // text search in title, actors, directors
	Genres          []domain.Genre
	Actors          []domain.Person
	Directors       []domain.Person
	Country         *string
	ReleaseYearFrom *int32
	ReleaseYearTo   *int32
	IMDbRatingFrom  *float32
	IMDbRatingTo    *float32

	Limit  int
	Offset int

	SortBy    string
	SortOrder string

	IncludeArchived bool
}
