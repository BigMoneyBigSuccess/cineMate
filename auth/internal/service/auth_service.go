package service

import "your_project/auth/internal/repository"

type AuthService struct {
	repo repository.AuthRepository
}

func NewAuthService(repo repository.AuthRepository) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) Register(email, password string) error {
	// TODO: hash password, check duplicates, save user
	return nil
}

func (s *AuthService) Login(email, password string) (string, error) {
	// TODO: validate credentials, generate JWT
	return "mock-token", nil
}

func (s *AuthService) ValidateToken(token string) (int64, error) {
	// TODO: parse token and return user id
	return 1, nil
}
