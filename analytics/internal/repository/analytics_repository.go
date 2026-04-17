package repository

type GenreStatRow struct {
	Genre string
	Count int32
}

type ActorStatRow struct {
	Actor string
	Count int32
}

type AnalyticsRepository interface {
	GetWatchedMoviesCount(userID int64) (int32, error)
	GetGenreStats(userID int64) ([]GenreStatRow, error)
	GetFavoriteActors(userID int64) ([]ActorStatRow, error)
}
