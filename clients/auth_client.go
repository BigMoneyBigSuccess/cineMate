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

func (c *AuthClient) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	resp, err := c.client.Register(ctx, &authv1.RegisterRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return uuid.Nil, err
	}
	userID, err := uuid.Parse(resp.UserId)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID format: %w", err)
	}
	return userID, nil
}

func (c *AuthClient) Login(ctx context.Context, email, password string) (string, error) {
	resp, err := c.client.Login(ctx, &authv1.LoginRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		return "", err
	}
	return resp.Token, nil
}

func (c *AuthClient) Logout(ctx context.Context, token string) error {
	_, err := c.client.Logout(ctx, &authv1.LogoutRequest{Token: token})
	return err
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
