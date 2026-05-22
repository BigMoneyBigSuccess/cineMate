package postgres

import (
	"context"
	"database/sql"

	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/ports"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var _ ports.ProfileRepository = (*ProfileRepository)(nil)

type ProfileRepository struct{ db *sql.DB }

func NewProfileRepository(db *sql.DB) *ProfileRepository { return &ProfileRepository{db: db} }

func (r *ProfileRepository) GetProfile(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	const q = `SELECT user_id, username, bio, created_at, updated_at
	           FROM user_profiles WHERE user_id = $1`
	var p domain.UserProfile
	err := r.db.QueryRowContext(ctx, q, userID).Scan(
		&p.UserID, &p.Username, &p.Bio, &p.CreatedAt, &p.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrProfileNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *ProfileRepository) SearchProfiles(ctx context.Context, query string, limit, offset int32) ([]domain.UserProfile, int32, error) {
	const q = `
		SELECT user_id, username, bio, created_at, updated_at,
		       COUNT(*) OVER() AS total
		FROM user_profiles
		WHERE username ILIKE '%' || $1 || '%'
		ORDER BY username
		LIMIT $2 OFFSET $3`
	rows, err := r.db.QueryContext(ctx, q, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var profiles []domain.UserProfile
	var total int32
	for rows.Next() {
		var p domain.UserProfile
		if err := rows.Scan(&p.UserID, &p.Username, &p.Bio, &p.CreatedAt, &p.UpdatedAt, &total); err != nil {
			return nil, 0, err
		}
		profiles = append(profiles, p)
	}
	return profiles, total, rows.Err()
}

func (r *ProfileRepository) UpsertProfile(ctx context.Context, p domain.UserProfile) error {
	const q = `
		INSERT INTO user_profiles (user_id, username, bio)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET
			username   = EXCLUDED.username,
			bio        = EXCLUDED.bio,
			updated_at = now()`
	_, err := r.db.ExecContext(ctx, q, p.UserID, p.Username, p.Bio)
	if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
		return domain.ErrUsernameTaken
	}
	return err
}
