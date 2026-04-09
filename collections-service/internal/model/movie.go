package model

type CollectionType string

const (
	Watched  CollectionType = "watched"
	Wishlist CollectionType = "wishlist"
)

type Movie struct {
	ID     int64   `json:"movie_id"`
	Rating float32 `json:"rating"`
	Review string  `json:"review"`
}
