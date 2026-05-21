package ports

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/google/uuid"
)

type ProfileRepository interface {
	GetProfile(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error)
	UpsertProfile(ctx context.Context, profile domain.UserProfile) error
	SearchProfiles(ctx context.Context, query string, limit, offset int32) ([]domain.UserProfile, int32, error)
}
