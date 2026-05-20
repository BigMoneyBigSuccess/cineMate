package usecase

import (
	"context"
	"movie_collection/internal/core/domain"
	"movie_collection/internal/core/ports"

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
