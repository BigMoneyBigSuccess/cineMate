package repository

type UserCollectionItemRow struct {
	MovieID     int64
	Title       string
	InWatchlist bool
	Watched     bool
	Rating      int32
	Review      string
}

type UserCollectionRepository interface {
	AddToWatchlist(userID, movieID int64) error
	MarkAsWatched(userID, movieID int64) error
	SaveRating(userID, movieID int64, rating int32) error
	SaveReview(userID, movieID int64, review string) error
	GetByUserID(userID int64) ([]UserCollectionItemRow, error)
}
