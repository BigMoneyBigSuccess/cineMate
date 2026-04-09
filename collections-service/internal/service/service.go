package service

import (
	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/model"
	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/repository"
)

type CollectionsService struct {
	repo *repository.CollectionsRepository
}

func NewCollectionService(repo *repository.CollectionsRepository) *CollectionsService {
	return &CollectionsService{repo: repo}
}

func (s *CollectionsService) AddMovie(userID string, ctype model.CollectionType, item model.Movie) error {
	return s.repo.AddMovie(userID, ctype, item)
}

func (s *CollectionsService) GetCollection(userID string, ctype model.CollectionType) ([]model.Movie, error) {
	return s.repo.GetCollection(userID, ctype)
}

func (s *CollectionsService) RemoveMovie(userID string, ctype model.CollectionType, movieID int64) error {
	return s.repo.RemoveMovie(userID, ctype, movieID)
}
