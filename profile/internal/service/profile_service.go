package service

import "github.com/BigMoneyBigSuccess/cineMate/profile/internal/repository"

type Profile struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Bio       string `json:"bio"`
	AvatarURL string `json:"avatar_url"`
}

type ProfileService struct {
	repo repository.ProfileRepository
}

func NewProfileService(repo repository.ProfileRepository) *ProfileService {
	return &ProfileService{repo: repo}
}

func (s *ProfileService) GetProfile(userID int64) (*Profile, error) {
	// TODO: получить профиль из repository
	return &Profile{
		UserID:    userID,
		Username:  "demo_user",
		Name:      "Demo User",
		Bio:       "movie lover",
		AvatarURL: "",
	}, nil
}

func (s *ProfileService) UpdateProfile(userID int64, username, name, bio, avatarURL string) error {
	// TODO: обновить профиль
	return nil
}
