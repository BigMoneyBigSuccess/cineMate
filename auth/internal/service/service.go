package service

import (
	"errors"

	"github.com/BigMoneyBigSuccess/cineMate/auth/internal/repository"
	"github.com/BigMoneyBigSuccess/cineMate/auth/internal/utils"
)

var (
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type AuthService struct {
	repo *repository.UserRepository
}

func NewAuthService(repo *repository.UserRepository) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) Register(email, password string) error {
	existingUser, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if existingUser != nil {
		return ErrUserExists
	}

	return s.repo.CreateUser(email, password)
}

func (s *AuthService) Login(email, password string) (string, error) {
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", ErrUserNotFound
	}

	if !utils.CheckPassword(user.Password, password) {
		return "", ErrInvalidCredentials
	}

	return utils.GenerateJWT(int64(user.ID))
}
