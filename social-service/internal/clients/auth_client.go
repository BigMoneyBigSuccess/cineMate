package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/proto/auth/authv1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AuthClient struct {
	client authv1.AuthServiceClient
	conn   *grpc.ClientConn
}

func NewAuthClient(host string, port int) (*AuthClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to auth service at %s: %w", addr, err)
	}
	return &AuthClient{client: authv1.NewAuthServiceClient(conn), conn: conn}, nil
}

func (c *AuthClient) ValidateToken(ctx context.Context, token string) (uuid.UUID, bool, string) {
	resp, err := c.client.ValidateToken(ctx, &authv1.ValidateTokenRequest{Token: token})
	if err != nil {
		return uuid.Nil, false, err.Error()
	}
	userID, err := uuid.Parse(resp.UserId)
	if err != nil {
		return uuid.Nil, false, "invalid user_id in token response"
	}
	return userID, resp.Valid, resp.Error
}

func (c *AuthClient) Close() error {
	return c.conn.Close()
}
