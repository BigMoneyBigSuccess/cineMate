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
	repo      ports.UserRepository
	social    ports.ProfileCreator
	blacklist ports.TokenBlacklist
}

func NewAuthUseCase(repo ports.UserRepository, social ports.ProfileCreator, blacklist ports.TokenBlacklist) *AuthUseCase {
	return &AuthUseCase{repo: repo, social: social, blacklist: blacklist}
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
	revoked, err := uc.blacklist.IsRevoked(ctx, utils.HashToken(token))
	if err != nil {
		return uuid.Nil, err
	}

	if revoked {
		return uuid.Nil, domain.ErrInvalidCredentials
	}

	return utils.ParseJWT(token)
}

func (uc *AuthUseCase) Logout(ctx context.Context, token string) error {
	exp, err := utils.GetTokenExpiry(token)
	if err != nil {
		return nil // already invalid, nothing to revoke
	}

	return uc.blacklist.Revoke(ctx, utils.HashToken(token), exp)
}
