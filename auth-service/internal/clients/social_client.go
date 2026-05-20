package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/proto/social/socialv1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var _ ports.ProfileCreator = (*SocialClient)(nil)

type SocialClient struct {
	client socialv1.SocialServiceClient
	conn   *grpc.ClientConn
}

func NewSocialClient(host string, port int) (*SocialClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to social service at %s: %w", addr, err)
	}
	return &SocialClient{client: socialv1.NewSocialServiceClient(conn), conn: conn}, nil
}

func (c *SocialClient) CreateProfile(ctx context.Context, userID uuid.UUID, username string) error {
	_, err := c.client.CreateProfile(ctx, &socialv1.CreateProfileRequest{
		UserId:   userID.String(),
		Username: username,
	})
	return err
}

func (c *SocialClient) Close() error {
	return c.conn.Close()
}
