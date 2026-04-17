package service

import "github.com/BigMoneyBigSuccess/cineMate/friends/internal/repository"

type Friend struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

type FriendsService struct {
	repo repository.FriendsRepository
}

func NewFriendsService(repo repository.FriendsRepository) *FriendsService {
	return &FriendsService{repo: repo}
}

func (s *FriendsService) SendFriendRequest(userID, friendID int64) error {
	// TODO: валидация и сохранение заявки
	return nil
}

func (s *FriendsService) AcceptFriendRequest(requestID int64) error {
	// TODO: принять заявку
	return nil
}

func (s *FriendsService) GetFriends(userID int64) ([]Friend, error) {
	// TODO: получить друзей из repository
	return []Friend{}, nil
}
