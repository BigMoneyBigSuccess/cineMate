package service

import "github.com/BigMoneyBigSuccess/cineMate/user_collection/internal/repository"

type UserCollectionItem struct {
	MovieID     int64  `json:"movie_id"`
	Title       string `json:"title"`
	InWatchlist bool   `json:"in_watchlist"`
	Watched     bool   `json:"watched"`
	Rating      int32  `json:"rating"`
	Review      string `json:"review"`
}

type UserCollectionService struct {
	repo repository.UserCollectionRepository
}

func NewUserCollectionService(repo repository.UserCollectionRepository) *UserCollectionService {
	return &UserCollectionService{repo: repo}
}

func (s *UserCollectionService) AddToWatchlist(userID, movieID int64) error {
	// TODO: добавить фильм в список "буду смотреть"
	return nil
}

func (s *UserCollectionService) MarkAsWatched(userID, movieID int64) error {
	// TODO: отметить фильм как просмотренный
	return nil
}

func (s *UserCollectionService) RateMovie(userID, movieID int64, rating int32) error {
	// TODO: сохранить оценку
	return nil
}

func (s *UserCollectionService) ReviewMovie(userID, movieID int64, review string) error {
	// TODO: сохранить отзыв
	return nil
}

func (s *UserCollectionService) GetUserCollection(userID int64) ([]UserCollectionItem, error) {
	// TODO: получить коллекцию пользователя
	return []UserCollectionItem{}, nil
}
