package grpc

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/api/proto/authv1"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/usecase"
)

type AuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	useCase *usecase.AuthUseCase
}

func NewAuthHandler(useCase *usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{useCase: useCase}
}

func (h *AuthHandler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	user, err := registerRequestToUser(req)
	if err != nil {
		return nil, err
	}

	id, err := h.useCase.Register(ctx, user.Email, user.Password)
	if err != nil {
		return nil, mapAuthError(err)
	}

	user.ID = id
	return userToRegisterResponse(&user), nil
}

func (h *AuthHandler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	email, password, err := loginRequestToCredentials(req)
	if err != nil {
		return nil, err
	}

	token, err := h.useCase.Login(ctx, email, password)
	if err != nil {
		return nil, mapAuthError(err)
	}

	return &authv1.LoginResponse{Token: token}, nil
}

func (h *AuthHandler) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	token, err := validateTokenRequestToToken(req)
	if err != nil {
		return nil, err
	}

	userID, err := h.useCase.ValidateToken(ctx, token)
	if err != nil {
		return &authv1.ValidateTokenResponse{Valid: false, Error: err.Error()}, nil
	}

	return &authv1.ValidateTokenResponse{UserId: userID.String(), Valid: true}, nil
}
