package usecase

import (
	"context"
	"fmt"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/utils"
	"github.com/google/uuid"
)

type AuthUseCase struct {
	repo   ports.UserRepository
	social ports.ProfileCreator
}

func NewAuthUseCase(repo ports.UserRepository, social ports.ProfileCreator) *AuthUseCase {
	return &AuthUseCase{repo: repo, social: social}
}

func (uc *AuthUseCase) Register(ctx context.Context, email, password string) (uuid.UUID, error) {
	user := domain.User{Email: email, Password: password}
	if err := user.Validate(); err != nil {
		return uuid.Nil, err
	}

	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}

	user.Password = hashedPassword
	id, err := uc.repo.CreateUser(ctx, user)
	if err != nil {
		return uuid.Nil, err
	}

	username := strings.SplitN(email, "@", 2)[0]
	if err := uc.social.CreateProfile(ctx, id, username); err != nil {
		return uuid.Nil, fmt.Errorf("create social profile: %w", err)
	}

	return id, nil
}

func (uc *AuthUseCase) Login(ctx context.Context, email, password string) (string, error) {
	user, err := uc.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", domain.ErrUserNotFound
	}

	if !utils.CheckPassword(user.Password, password) {
		return "", domain.ErrInvalidCredentials
	}

	return utils.GenerateJWT(user.ID.String())
}

func (uc *AuthUseCase) ValidateToken(ctx context.Context, token string) (uuid.UUID, error) {
	return utils.ParseJWT(token)
}
