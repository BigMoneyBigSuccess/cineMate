package postgres

import (
	"context"
	"database/sql"
	"movie_collection/internal/core/domain"
	"movie_collection/internal/core/ports"

	"github.com/google/uuid"
)

var _ ports.WatchlistRepository = (*WatchlistRepository)(nil)

type WatchlistRepository struct {
	db *sql.DB
}

func NewWatchlistRepository(db *sql.DB) *WatchlistRepository {
	return &WatchlistRepository{db: db}
}

func (r *WatchlistRepository) AddMovie(ctx context.Context, userID, movieID uuid.UUID) error {
	_, err := r.db.ExecContext(
		ctx,
		`INSERT INTO watchlists (user_id, movie_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		userID,
		movieID,
	)
	return err
}

func (r *WatchlistRepository) RemoveMovie(ctx context.Context, userID, movieID uuid.UUID) error {
	_, err := r.db.ExecContext(
		ctx,
		`DELETE FROM watchlists
		WHERE user_id = $1
		  AND movie_id = $2`,
		userID,
		movieID,
	)
	return err
}

func (r *WatchlistRepository) GetUserWatchlist(ctx context.Context, userID uuid.UUID) ([]domain.Movie, error) {
	rows, err := r.db.QueryContext(
		ctx,
		`SELECT movie_id
		FROM watchlists
		WHERE user_id = $1
		ORDER BY added_at DESC, movie_id`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var movieID uuid.UUID
		if err := rows.Scan(&movieID); err != nil {
			return nil, err
		}
		ids = append(ids, movieID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return (&MovieRepository{db: r.db}).loadMoviesByIDs(ctx, ids)
}
