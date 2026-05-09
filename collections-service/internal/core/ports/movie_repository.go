package ports

import (
	"context"
	"movie_collection/internal/core/domain"

	"github.com/google/uuid"
)

type MovieRepository interface {
	UpsertMovie(ctx context.Context, movie domain.Movie) error
	ArchiveMovie(ctx context.Context, id uuid.UUID) error
	RemoveMovie(ctx context.Context, id uuid.UUID) error
	GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.Movie, error)
	List(ctx context.Context, filter MovieFilter) ([]domain.Movie, error)
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
