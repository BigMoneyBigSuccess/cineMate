package ports

import (
	"context"

	"github.com/google/uuid"
)

type FollowRepository interface {
	Follow(ctx context.Context, followerID, followedID uuid.UUID) error
	Unfollow(ctx context.Context, followerID, followedID uuid.UUID) error
	GetFollowers(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]uuid.UUID, int32, error)
	GetFollowing(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]uuid.UUID, int32, error)
	IsFollowing(ctx context.Context, followerID, followedID uuid.UUID) (bool, error)
}
