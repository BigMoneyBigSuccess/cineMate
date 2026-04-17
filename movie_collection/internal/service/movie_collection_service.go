package service

import "github.com/BigMoneyBigSuccess/cineMate/movie_collection/internal/repository"

type CollectionItem struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Rating   int32  `json:"rating"`
	Review   string `json:"review"`
	Watched  bool   `json:"watched"`
}

type MovieCollectionService struct {
	repo repository.MovieCollectionRepository
}

func NewMovieCollectionService(repo repository.MovieCollectionRepository) *MovieCollectionService {
	return &MovieCollectionService{repo: repo}
}

func (s *MovieCollectionService) GetMovieCollections(movieID int64) ([]CollectionItem, error) {
	// TODO: получить коллекции пользователей по фильму
	return []CollectionItem{}, nil
}
