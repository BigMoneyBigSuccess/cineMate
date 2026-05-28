package grpc

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/proto/auth/authv1"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func registerRequestToUser(req *authv1.RegisterRequest) (domain.User, error) {
	if req == nil {
		return domain.User{}, status.Error(codes.InvalidArgument, "register request is required")
	}

	email := strings.TrimSpace(req.GetEmail())
	password := strings.TrimSpace(req.GetPassword())

	if email == "" || password == "" {
		return domain.User{}, status.Error(codes.InvalidArgument, "email and password are required")
	}

	user := domain.User{
		Email:    email,
		Password: password,
	}

	if err := user.Validate(); err != nil {
		return domain.User{}, status.Error(codes.InvalidArgument, err.Error())
	}

	return user, nil
}

func userToRegisterResponse(user *domain.User) *authv1.RegisterResponse {
	if user == nil {
		return &authv1.RegisterResponse{}
	}
	return &authv1.RegisterResponse{
		UserId: user.ID.String(),
	}
}

func loginRequestToCredentials(req *authv1.LoginRequest) (email, password string, err error) {
	if req == nil {
		return "", "", status.Error(codes.InvalidArgument, "login request is required")
	}

	email = strings.TrimSpace(req.GetEmail())
	password = strings.TrimSpace(req.GetPassword())

	if email == "" || password == "" {
		return "", "", status.Error(codes.InvalidArgument, "email and password are required")
	}

	return email, password, nil
}

func validateTokenRequestToToken(req *authv1.ValidateTokenRequest) (string, error) {
	if req == nil {
		return "", status.Error(codes.InvalidArgument, "validate token request is required")
	}

	token := strings.TrimSpace(req.GetToken())
	if token == "" {
		return "", status.Error(codes.InvalidArgument, "token is required")
	}

	return token, nil
}

func mapAuthError(err error) error {
	switch {
	case err == nil:
		return nil
	case status.Code(err) != codes.Unknown:
		
		return err
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, context.Canceled.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
	case errors.Is(err, sql.ErrNoRows):
		return status.Error(codes.NotFound, "user not found")
	case err == domain.ErrUserExists:
		return status.Error(codes.AlreadyExists, err.Error())
	case err == domain.ErrUserNotFound:
		return status.Error(codes.NotFound, err.Error())
	case err == domain.ErrInvalidCredentials:
		return status.Error(codes.Unauthenticated, err.Error())
	case err == domain.ErrInvalidUser:
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
