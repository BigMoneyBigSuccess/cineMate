package postgres

import (
	"context"
	"fmt"

<<<<<<< HEAD
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"
=======
	"movie_service/internal/core/domain"
	"movie_service/internal/core/ports"
>>>>>>> 26ab2e2 (took out environment variables into .env file & added syncer for fetching films from open api service & took out proto files from movie-service, now they will lie in shared directory)

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ ports.WatchlistRepository = (*WatchlistRepository)(nil)

type WatchlistRepository struct {
	db *pgxpool.Pool
}

func NewWatchlistRepository(db *pgxpool.Pool) *WatchlistRepository {
	return &WatchlistRepository{db: db}
}

func (r *WatchlistRepository) AddMovie(ctx context.Context, userID, movieID uuid.UUID) error {
	const q = `
		INSERT INTO watchlists (user_id, movie_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`

	if _, err := r.db.Exec(ctx, q, userID, movieID); err != nil {
		return fmt.Errorf("add movie to watchlist: %w", err)
	}
	return nil
}

func (r *WatchlistRepository) RemoveMovie(ctx context.Context, userID, movieID uuid.UUID) error {
	const q = `
		DELETE FROM watchlists
		WHERE user_id = $1
		  AND movie_id = $2`

	if _, err := r.db.Exec(ctx, q, userID, movieID); err != nil {
		return fmt.Errorf("remove movie from watchlist: %w", err)
	}
	return nil
}

func (r *WatchlistRepository) GetUserWatchlist(ctx context.Context, userID uuid.UUID) ([]domain.Movie, error) {
	const q = `
		SELECT movie_id
		FROM watchlists
		WHERE user_id = $1
		ORDER BY added_at DESC, movie_id`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("query watchlist: %w", err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var movieID uuid.UUID
		if err := rows.Scan(&movieID); err != nil {
			return nil, fmt.Errorf("scan watchlist row: %w", err)
		}
		ids = append(ids, movieID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate watchlist rows: %w", err)
	}

	return (&MovieRepository{db: r.db}).loadMoviesByIDs(ctx, ids)
}

var _ ports.WatchlistRepository = (*WatchlistRepository)(nil)
