package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/logger"
	"github.com/BigMoneyBigSuccess/cineMate/proto/social/socialv1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type SocialClient struct {
	client socialv1.SocialServiceClient
	conn   *grpc.ClientConn
}

func NewSocialClient(host string, port int) (*SocialClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(logger.UnaryClientInterceptor()),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to social service at %s: %w", addr, err)
	}
	return &SocialClient{client: socialv1.NewSocialServiceClient(conn), conn: conn}, nil
}

func (c *SocialClient) Close() error { return c.conn.Close() }

func withToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func (c *SocialClient) CreateProfile(ctx context.Context, userID uuid.UUID, username string) error {
	_, err := c.client.CreateProfile(ctx, &socialv1.CreateProfileRequest{
		UserId:   userID.String(),
		Username: username,
	})
	return err
}

func (c *SocialClient) GetProfile(ctx context.Context, userID string) (*socialv1.UserProfile, error) {
	resp, err := c.client.GetProfile(ctx, &socialv1.GetProfileRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return resp.Profile, nil
}

func (c *SocialClient) UpdateProfile(ctx context.Context, token, username, bio string) error {
	_, err := c.client.UpdateProfile(withToken(ctx, token), &socialv1.UpdateProfileRequest{
		Username: username,
		Bio:      bio,
	})
	return err
}

func (c *SocialClient) FollowUser(ctx context.Context, token, followedID string) error {
	_, err := c.client.FollowUser(withToken(ctx, token), &socialv1.FollowUserRequest{FollowedId: followedID})
	return err
}

func (c *SocialClient) UnfollowUser(ctx context.Context, token, followedID string) error {
	_, err := c.client.UnfollowUser(withToken(ctx, token), &socialv1.UnfollowUserRequest{FollowedId: followedID})
	return err
}

func (c *SocialClient) GetFollowers(ctx context.Context, userID string, limit, offset int32) (*socialv1.GetFollowersResponse, error) {
	return c.client.GetFollowers(ctx, &socialv1.GetFollowersRequest{UserId: userID, Limit: limit, Offset: offset})
}

func (c *SocialClient) GetFollowing(ctx context.Context, userID string, limit, offset int32) (*socialv1.GetFollowingResponse, error) {
	return c.client.GetFollowing(ctx, &socialv1.GetFollowingRequest{UserId: userID, Limit: limit, Offset: offset})
}

func (c *SocialClient) IsFollowing(ctx context.Context, followerID, followedID string) (bool, error) {
	resp, err := c.client.IsFollowing(ctx, &socialv1.IsFollowingRequest{FollowerId: followerID, FollowedId: followedID})
	if err != nil {
		return false, err
	}
	return resp.IsFollowing, nil
}

func (c *SocialClient) SearchUsers(ctx context.Context, query string, limit, offset int32) (*socialv1.SearchUsersResponse, error) {
	return c.client.SearchUsers(ctx, &socialv1.SearchUsersRequest{Query: query, Limit: limit, Offset: offset})
}
