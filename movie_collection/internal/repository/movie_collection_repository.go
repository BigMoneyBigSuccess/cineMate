package repository

type CollectionItemRow struct {
	UserID   int64
	Username string
	Rating   int32
	Review   string
	Watched  bool
}

type MovieCollectionRepository interface {
	GetByMovieID(movieID int64) ([]CollectionItemRow, error)
}
