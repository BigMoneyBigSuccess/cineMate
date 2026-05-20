package ports

import (
	"context"
<<<<<<< HEAD

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
=======
	"movie_service/internal/core/domain"
>>>>>>> 26ab2e2 (took out environment variables into .env file & added syncer for fetching films from open api service & took out proto files from movie-service, now they will lie in shared directory)

	"github.com/google/uuid"
)

type WatchlistRepository interface {
	AddMovie(ctx context.Context, userID, movieID uuid.UUID) error
	RemoveMovie(ctx context.Context, userID, movieID uuid.UUID) error
	GetUserWatchlist(ctx context.Context, userID uuid.UUID) ([]domain.Movie, error)
}
