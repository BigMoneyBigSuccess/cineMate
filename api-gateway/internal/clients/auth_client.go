package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/api/proto/authv1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AuthClient struct {
	client authv1.AuthServiceClient
	conn   *grpc.ClientConn
}

func NewAuthClient(ctx context.Context, host string, port int) (*AuthClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		return nil, fmt.Errorf("connect to auth service at %s: %w", addr, err)
	}

	return &AuthClient{
		client: authv1.NewAuthServiceClient(conn),
		conn:   conn,
	}, nil
}

func (ac *AuthClient) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	resp, err := ac.client.Register(ctx, &authv1.RegisterRequest{
		Email:    email,
		Password: password,
	})

	if err != nil {
		return uuid.Nil, err
	}

	user_id, err := uuid.Parse(resp.UserId)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	return user_id, nil
}

func (ac *AuthClient) Login(ctx context.Context, email, password string) (string, error) {
	resp, err := ac.client.Login(ctx, &authv1.LoginRequest{
		Email:    email,
		Password: password,
	})

	if err != nil {
		return "", err
	}
	return resp.Token, nil
}

func (ac *AuthClient) ValidateToken(ctx context.Context, token string) (uuid.UUID, bool, string) {
	resp, err := ac.client.ValidateToken(ctx, &authv1.ValidateTokenRequest{
		Token: token,
	})

	user_id, err := uuid.Parse(resp.UserId)
	if err != nil {
		return uuid.Nil, false, "invalid user ID format"
	}

	return user_id, resp.Valid, resp.Error
}

func (ac *AuthClient) Close() error {
	return ac.conn.Close()
}
