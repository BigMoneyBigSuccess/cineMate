package postgres

import (
	"context"
	"database/sql"

	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/ports"
	"github.com/google/uuid"
)

var _ ports.FollowRepository = (*FollowRepository)(nil)

type FollowRepository struct{ db *sql.DB }

func NewFollowRepository(db *sql.DB) *FollowRepository { return &FollowRepository{db: db} }

func (r *FollowRepository) Follow(ctx context.Context, followerID, followedID uuid.UUID) error {
	const q = `INSERT INTO follows (follower_id, followed_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	res, err := r.db.ExecContext(ctx, q, followerID, followedID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrAlreadyFollows
	}
	return nil
}

func (r *FollowRepository) Unfollow(ctx context.Context, followerID, followedID uuid.UUID) error {
	const q = `DELETE FROM follows WHERE follower_id = $1 AND followed_id = $2`
	res, err := r.db.ExecContext(ctx, q, followerID, followedID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrNotFollowing
	}
	return nil
}

func (r *FollowRepository) GetFollowers(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]uuid.UUID, int32, error) {
	var total int32
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM follows WHERE followed_id = $1`, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT follower_id FROM follows WHERE followed_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	return scanUUIDs(rows, total)
}

func (r *FollowRepository) GetFollowing(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]uuid.UUID, int32, error) {
	var total int32
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM follows WHERE follower_id = $1`, userID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT followed_id FROM follows WHERE follower_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	return scanUUIDs(rows, total)
}

func (r *FollowRepository) IsFollowing(ctx context.Context, followerID, followedID uuid.UUID) (bool, error) {
	var dummy int
	err := r.db.QueryRowContext(ctx,
		`SELECT 1 FROM follows WHERE follower_id = $1 AND followed_id = $2 LIMIT 1`,
		followerID, followedID).Scan(&dummy)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func scanUUIDs(rows *sql.Rows, total int32) ([]uuid.UUID, int32, error) {
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, 0, err
		}
		ids = append(ids, id)
	}
	return ids, total, rows.Err()
}
