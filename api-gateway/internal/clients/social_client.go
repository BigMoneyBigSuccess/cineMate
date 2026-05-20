package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/social-service/api/proto/socialv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type SocialClient struct {
	client socialv1.SocialServiceClient
	conn   *grpc.ClientConn
}

func NewSocialClient(ctx context.Context, host string, port int) (*SocialClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to social service at %s: %w", addr, err)
	}
	return &SocialClient{client: socialv1.NewSocialServiceClient(conn), conn: conn}, nil
}

func (c *SocialClient) Close() error { return c.conn.Close() }

func withToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func (c *SocialClient) GetProfile(ctx context.Context, userID string) (*socialv1.UserProfile, error) {
	resp, err := c.client.GetProfile(ctx, &socialv1.GetProfileRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return resp.Profile, nil
}

func (c *SocialClient) UpdateProfile(ctx context.Context, token, username, avatarURL, bio string) error {
	_, err := c.client.UpdateProfile(withToken(ctx, token), &socialv1.UpdateProfileRequest{
		Username:  username,
		AvatarUrl: avatarURL,
		Bio:       bio,
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

func (c *SocialClient) AddToWatchlist(ctx context.Context, token, movieID string) error {
	_, err := c.client.AddToWatchlist(withToken(ctx, token), &socialv1.MovieListEntryRequest{MovieId: movieID})
	return err
}

func (c *SocialClient) RemoveFromWatchlist(ctx context.Context, token, movieID string) error {
	_, err := c.client.RemoveFromWatchlist(withToken(ctx, token), &socialv1.MovieListEntryRequest{MovieId: movieID})
	return err
}

func (c *SocialClient) GetWatchlist(ctx context.Context, userID string, limit, offset int32) (*socialv1.GetMovieListResponse, error) {
	return c.client.GetWatchlist(ctx, &socialv1.GetMovieListRequest{UserId: userID, Limit: limit, Offset: offset})
}

func (c *SocialClient) MarkWatched(ctx context.Context, token, movieID string) error {
	_, err := c.client.MarkWatched(withToken(ctx, token), &socialv1.MovieListEntryRequest{MovieId: movieID})
	return err
}

func (c *SocialClient) UnmarkWatched(ctx context.Context, token, movieID string) error {
	_, err := c.client.UnmarkWatched(withToken(ctx, token), &socialv1.MovieListEntryRequest{MovieId: movieID})
	return err
}

func (c *SocialClient) GetWatched(ctx context.Context, userID string, limit, offset int32) (*socialv1.GetMovieListResponse, error) {
	return c.client.GetWatched(ctx, &socialv1.GetMovieListRequest{UserId: userID, Limit: limit, Offset: offset})
}
