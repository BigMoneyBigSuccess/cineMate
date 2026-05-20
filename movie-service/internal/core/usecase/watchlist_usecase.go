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

type WatchlistUseCase struct {
	watchlist ports.WatchlistRepository
}

func NewWatchlistUseCase(watchlist ports.WatchlistRepository) *WatchlistUseCase {
	return &WatchlistUseCase{watchlist: watchlist}
}

func (uc *WatchlistUseCase) AddMovieToWatchlist(ctx context.Context, userID, movieID uuid.UUID) error {
	return uc.watchlist.AddMovie(ctx, userID, movieID)
}

func (uc *WatchlistUseCase) RemoveMovieFromWatchlist(ctx context.Context, userID, movieID uuid.UUID) error {
	return uc.watchlist.RemoveMovie(ctx, userID, movieID)
}

func (uc *WatchlistUseCase) GetUserWatchlist(ctx context.Context, userID uuid.UUID) ([]domain.Movie, error) {
	return uc.watchlist.GetUserWatchlist(ctx, userID)
}
