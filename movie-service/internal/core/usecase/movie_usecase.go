package usecase

import (
	"context"
<<<<<<< HEAD

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"
=======
	"movie_service/internal/core/domain"
	"movie_service/internal/core/ports"
>>>>>>> 26ab2e2 (took out environment variables into .env file & added syncer for fetching films from open api service & took out proto files from movie-service, now they will lie in shared directory)

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
