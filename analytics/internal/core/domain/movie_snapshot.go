package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type MovieSnapshot struct {
	MovieID     uuid.UUID `json:"movie_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Genres      []Genre   `json:"genres"`
	Actors      []Person  `json:"actors"`
	Directors   []Person  `json:"directors"`
	Country     string    `json:"country"`
	ReleaseYear int32     `json:"release_year"`
	IMDbRating  float32   `json:"imdb_rating"`
}

func (m MovieSnapshot) Validate() error {
	if m.MovieID == uuid.Nil {
		return ErrInvalidMovieSnapshot
	}
	if strings.TrimSpace(m.Title) == "" || strings.TrimSpace(m.Description) == "" || strings.TrimSpace(m.Country) == "" {
		return ErrInvalidMovieSnapshot
	}
	if len(m.Genres) == 0 || len(m.Actors) == 0 || len(m.Directors) == 0 {
		return ErrInvalidMovieSnapshot
	}
	if m.ReleaseYear < 1888 || m.ReleaseYear > int32(time.Now().Year()) {
		return ErrInvalidMovieSnapshot
	}
	if m.IMDbRating < 0 || m.IMDbRating > 10 {
		return ErrInvalidMovieSnapshot
	}

	return nil
}
