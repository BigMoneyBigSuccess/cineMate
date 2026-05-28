package ports

import (
	"context"
	"time"
)

type TokenBlacklist interface {
	Revoke(ctx context.Context, tokenHash string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, tokenHash string) (bool, error)
}
