package service

import "github.com/BigMoneyBigSuccess/cineMate/analytics/internal/repository"

type GenreStat struct {
	Genre string `json:"genre"`
	Count int32  `json:"count"`
}

type ActorStat struct {
	Actor string `json:"actor"`
	Count int32  `json:"count"`
}

type UserStats struct {
	WatchedMovies  int32       `json:"watched_movies"`
	Genres         []GenreStat `json:"genres"`
	FavoriteActors []ActorStat `json:"favorite_actors"`
}

type AnalyticsService struct {
	repo repository.AnalyticsRepository
}

func NewAnalyticsService(repo repository.AnalyticsRepository) *AnalyticsService {
	return &AnalyticsService{repo: repo}
}

func (s *AnalyticsService) GetUserStats(userID int64) (*UserStats, error) {
	// TODO: собрать статистику из repository
	return &UserStats{
		WatchedMovies: 0,
		Genres:        []GenreStat{},
		FavoriteActors: []ActorStat{},
	}, nil
}
