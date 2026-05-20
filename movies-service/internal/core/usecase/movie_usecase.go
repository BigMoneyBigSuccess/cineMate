package usecase

import (
	"context"
	"movie_collection/internal/core/domain"
	"movie_collection/internal/core/ports"

	"github.com/google/uuid"
)

type MovieUseCase struct {
	movies ports.MovieRepository
}

func NewMovieUseCase(movies ports.MovieRepository) *MovieUseCase {
	return &MovieUseCase{movies: movies}
}

func (uc *MovieUseCase) UpsertMovieInRepository(ctx context.Context, movie domain.Movie) error {
	if err := movie.Validate(); err != nil {
		return err
	}
	return uc.movies.UpsertMovie(ctx, movie)
}

func (uc *MovieUseCase) ArchiveMovieInRepository(ctx context.Context, id uuid.UUID) error {
	return uc.movies.ArchiveMovie(ctx, id)
}

func (uc *MovieUseCase) RemoveMovieFromRepository(ctx context.Context, id uuid.UUID) error {
	return uc.movies.RemoveMovie(ctx, id)
}

func (uc *MovieUseCase) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.Movie, error) {
	return uc.movies.GetMovieByID(ctx, id)
}

func (uc *MovieUseCase) ListMovies(ctx context.Context, filter ports.MovieFilter) ([]domain.Movie, error) {
	return uc.movies.ListMovies(ctx, filter)
}
