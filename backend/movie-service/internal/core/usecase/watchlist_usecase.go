package usecase

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/logger"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"

	"github.com/google/uuid"
)

type WatchlistUseCase struct {
	watchlist ports.WatchlistRepository
}

func NewWatchlistUseCase(watchlist ports.WatchlistRepository) *WatchlistUseCase {
	return &WatchlistUseCase{watchlist: watchlist}
}

func (uc *WatchlistUseCase) AddMovieToWatchlist(ctx context.Context, userID, movieID uuid.UUID) error {
	if err := uc.watchlist.AddMovie(ctx, userID, movieID); err != nil {
		return err
	}
	logger.FromContext(ctx).Info("watchlist movie added", "user_id", userID, "movie_id", movieID)
	return nil
}

func (uc *WatchlistUseCase) RemoveMovieFromWatchlist(ctx context.Context, userID, movieID uuid.UUID) error {
	if err := uc.watchlist.RemoveMovie(ctx, userID, movieID); err != nil {
		return err
	}
	logger.FromContext(ctx).Info("watchlist movie removed", "user_id", userID, "movie_id", movieID)
	return nil
}

func (uc *WatchlistUseCase) GetUserWatchlist(ctx context.Context, userID uuid.UUID) ([]domain.Movie, error) {
	return uc.watchlist.GetUserWatchlist(ctx, userID)
}
