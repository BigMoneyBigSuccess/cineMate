package model

type Movie struct {
	ID     int64   `json:"movie_id"`
	Rating float32 `json:"rating"`
	Review string  `json:"review"`
}
