package ports

import (
	"context"
	"movie_collection/internal/core/domain"

	"github.com/google/uuid"
)

type WatchlistRepository interface {
	AddMovie(ctx context.Context, userID, movieID uuid.UUID) error
	RemoveMovie(ctx context.Context, userID, movieID uuid.UUID) error
	GetUserWatchlist(ctx context.Context, userID uuid.UUID) ([]domain.Movie, error)
}
