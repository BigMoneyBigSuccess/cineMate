package usecase

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/logger"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/ports"
	"github.com/google/uuid"
)

type SocialUseCase struct {
	profiles ports.ProfileRepository
	follows  ports.FollowRepository
}

func NewSocialUseCase(
	profiles ports.ProfileRepository,
	follows ports.FollowRepository,
) *SocialUseCase {
	return &SocialUseCase{profiles: profiles, follows: follows}
}

func (uc *SocialUseCase) GetProfile(ctx context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	return uc.profiles.GetProfile(ctx, userID)
}

func (uc *SocialUseCase) UpdateProfile(ctx context.Context, profile domain.UserProfile) error {
	return uc.profiles.UpsertProfile(ctx, profile)
}

func (uc *SocialUseCase) FollowUser(ctx context.Context, followerID, followedID uuid.UUID) error {
	if err := uc.follows.Follow(ctx, followerID, followedID); err != nil {
		return err
	}
	logger.FromContext(ctx).Info("follow created", "follower_id", followerID, "followed_id", followedID)
	return nil
}

func (uc *SocialUseCase) UnfollowUser(ctx context.Context, followerID, followedID uuid.UUID) error {
	if err := uc.follows.Unfollow(ctx, followerID, followedID); err != nil {
		return err
	}
	logger.FromContext(ctx).Info("follow removed", "follower_id", followerID, "followed_id", followedID)
	return nil
}

func (uc *SocialUseCase) GetFollowers(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]uuid.UUID, int32, error) {
	return uc.follows.GetFollowers(ctx, userID, limit, offset)
}

func (uc *SocialUseCase) GetFollowing(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]uuid.UUID, int32, error) {
	return uc.follows.GetFollowing(ctx, userID, limit, offset)
}

func (uc *SocialUseCase) IsFollowing(ctx context.Context, followerID, followedID uuid.UUID) (bool, error) {
	return uc.follows.IsFollowing(ctx, followerID, followedID)
}

func (uc *SocialUseCase) SearchUsers(ctx context.Context, query string, limit, offset int32) ([]domain.UserProfile, int32, error) {
	return uc.profiles.SearchProfiles(ctx, query, limit, offset)
}
