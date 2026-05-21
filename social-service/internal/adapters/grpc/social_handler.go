package grpc

import (
	"context"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/proto/social/socialv1"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/usecase"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SocialHandler struct {
	socialv1.UnimplementedSocialServiceServer
	useCase *usecase.SocialUseCase
}

func NewSocialHandler(useCase *usecase.SocialUseCase) *SocialHandler {
	return &SocialHandler{useCase: useCase}
}

func (h *SocialHandler) CreateProfile(ctx context.Context, req *socialv1.CreateProfileRequest) (*emptypb.Empty, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	profile := domain.UserProfile{
		UserID:   userID,
		Username: strings.TrimSpace(req.GetUsername()),
	}

	if err := h.useCase.UpdateProfile(ctx, profile); err != nil {
		return nil, mapSocialError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *SocialHandler) GetProfile(ctx context.Context, req *socialv1.GetProfileRequest) (*socialv1.GetProfileResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	profile, err := h.useCase.GetProfile(ctx, userID)
	if err != nil {
		return nil, mapSocialError(err)
	}

	return &socialv1.GetProfileResponse{
		Profile: &socialv1.UserProfile{
			UserId:    profile.UserID.String(),
			Username:  profile.Username,
			Bio:       profile.Bio,
			CreatedAt: timestamppb.New(profile.CreatedAt),
			UpdatedAt: timestamppb.New(profile.UpdatedAt),
		},
	}, nil
}

func (h *SocialHandler) UpdateProfile(ctx context.Context, req *socialv1.UpdateProfileRequest) (*emptypb.Empty, error) {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user_id in context")
	}

	profile := domain.UserProfile{
		UserID:   userID,
		Username: strings.TrimSpace(req.GetUsername()),
		Bio:      strings.TrimSpace(req.GetBio()),
	}

	if err := h.useCase.UpdateProfile(ctx, profile); err != nil {
		return nil, mapSocialError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *SocialHandler) FollowUser(ctx context.Context, req *socialv1.FollowUserRequest) (*emptypb.Empty, error) {
	followerID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user_id in context")
	}

	followedID, err := uuid.Parse(req.GetFollowedId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid followed_id")
	}

	if err := h.useCase.FollowUser(ctx, followerID, followedID); err != nil {
		return nil, mapSocialError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *SocialHandler) UnfollowUser(ctx context.Context, req *socialv1.UnfollowUserRequest) (*emptypb.Empty, error) {
	followerID, ok := UserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing user_id in context")
	}

	followedID, err := uuid.Parse(req.GetFollowedId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid followed_id")
	}

	if err := h.useCase.UnfollowUser(ctx, followerID, followedID); err != nil {
		return nil, mapSocialError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *SocialHandler) GetFollowers(ctx context.Context, req *socialv1.GetFollowersRequest) (*socialv1.GetFollowersResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	ids, total, err := h.useCase.GetFollowers(ctx, userID, req.GetLimit(), req.GetOffset())
	if err != nil {
		return nil, mapSocialError(err)
	}

	return &socialv1.GetFollowersResponse{
		FollowerIds: uuidsToStrings(ids),
		Total:       total,
	}, nil
}

func (h *SocialHandler) GetFollowing(ctx context.Context, req *socialv1.GetFollowingRequest) (*socialv1.GetFollowingResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id")
	}

	ids, total, err := h.useCase.GetFollowing(ctx, userID, req.GetLimit(), req.GetOffset())
	if err != nil {
		return nil, mapSocialError(err)
	}

	return &socialv1.GetFollowingResponse{
		FollowingIds: uuidsToStrings(ids),
		Total:        total,
	}, nil
}

func (h *SocialHandler) IsFollowing(ctx context.Context, req *socialv1.IsFollowingRequest) (*socialv1.IsFollowingResponse, error) {
	followerID, err := uuid.Parse(req.GetFollowerId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid follower_id")
	}

	followedID, err := uuid.Parse(req.GetFollowedId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid followed_id")
	}

	isFollowing, err := h.useCase.IsFollowing(ctx, followerID, followedID)
	if err != nil {
		return nil, mapSocialError(err)
	}

	return &socialv1.IsFollowingResponse{IsFollowing: isFollowing}, nil
}

func (h *SocialHandler) SearchUsers(ctx context.Context, req *socialv1.SearchUsersRequest) (*socialv1.SearchUsersResponse, error) {
	profiles, total, err := h.useCase.SearchUsers(ctx, req.GetQuery(), req.GetLimit(), req.GetOffset())
	if err != nil {
		return nil, mapSocialError(err)
	}

	out := make([]*socialv1.UserProfile, len(profiles))
	for i, p := range profiles {
		out[i] = &socialv1.UserProfile{
			UserId:    p.UserID.String(),
			Username:  p.Username,
			Bio:       p.Bio,
			CreatedAt: timestamppb.New(p.CreatedAt),
			UpdatedAt: timestamppb.New(p.UpdatedAt),
		}
	}
	return &socialv1.SearchUsersResponse{Profiles: out, Total: total}, nil
}

func uuidsToStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
