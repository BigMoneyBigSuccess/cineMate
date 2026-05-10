package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type Movie struct {
	MovieID       uuid.UUID  `json:"movie_id"`
	Title         string     `json:"title"`
	Description   string     `json:"description"`
	Genres        []Genre    `json:"genres"`
	Actors        []Person   `json:"actors"`
	Directors     []Person   `json:"directors"`
	Country       string     `json:"country"`
	ReleaseYear   int32      `json:"release_year"`
	IMDbRating    float32    `json:"imdb_rating"`
	Source        string     `json:"source"`
	SourceMovieID string     `json:"source_movie_id"`
	LastSyncAt    time.Time  `json:"last_sync_at"`
	ArchivedAt    *time.Time `json:"archived_at,omitempty"`
}

func (m Movie) Validate() error {
	if strings.TrimSpace(m.Title) == "" || strings.TrimSpace(m.Country) == "" {
		return ErrInvalidMovie
	}
	if strings.TrimSpace(m.Source) == "" || strings.TrimSpace(m.SourceMovieID) == "" {
		return ErrInvalidMovie
	}
	if len(m.Genres) == 0 || len(m.Actors) == 0 || len(m.Directors) == 0 {
		return ErrInvalidMovie
	}
	if m.ReleaseYear < 1888 || m.ReleaseYear > int32(time.Now().Year()) {
		return ErrInvalidMovie
	}
	if m.IMDbRating < 0 || m.IMDbRating > 10 {
		return ErrInvalidMovie
	}
	for _, genre := range m.Genres {
		if err := genre.Validate(); err != nil {
			return ErrInvalidMovie
		}
	}
	for _, actor := range m.Actors {
		if err := actor.Validate(); err != nil {
			return ErrInvalidMovie
		}
	}
	for _, director := range m.Directors {
		if err := director.Validate(); err != nil {
			return ErrInvalidMovie
		}
	}
	return nil
}
