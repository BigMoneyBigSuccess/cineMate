package ports

import (
	"context"

	"analytics/internal/core/domain"

	"github.com/google/uuid"
)

// UserProfileRepository stores the explicit preference profile that serves as
// the main personalization baseline for the user.
type UserProfileRepository interface {
	UpsertProfile(ctx context.Context, profile domain.UserPreferenceProfile) error
	RemoveProfile(ctx context.Context, userID uuid.UUID) error
	// GetOrCreateProfileByUserID returns the stored profile or an empty one if
	// none exists yet. Callers never receive a nil value.
	GetOrCreateProfileByUserID(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error)
}
