package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/ports"
)

var _ ports.TokenBlacklist = (*TokenBlacklistRepository)(nil)

type TokenBlacklistRepository struct{ db *sql.DB }

func NewTokenBlacklistRepository(db *sql.DB) *TokenBlacklistRepository {
	return &TokenBlacklistRepository{db: db}
}

func (r *TokenBlacklistRepository) Revoke(ctx context.Context, tokenHash string, expiresAt time.Time) error {
	const q = `
		INSERT INTO revoked_tokens (token_hash, expires_at) VALUES ($1, $2)
		ON CONFLICT (token_hash) DO NOTHING`
	// clean up already-expired tokens on every revoke
	_, _ = r.db.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE expires_at < now()`)
	_, err := r.db.ExecContext(ctx, q, tokenHash, expiresAt)
	return err
}

func (r *TokenBlacklistRepository) IsRevoked(ctx context.Context, tokenHash string) (bool, error) {
	const q = `SELECT 1 FROM revoked_tokens WHERE token_hash = $1 AND expires_at > now() LIMIT 1`
	var exists int
	err := r.db.QueryRowContext(ctx, q, tokenHash).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}

	return err == nil, err
}
