package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type Movie struct {
	MovieID       uuid.UUID  `json:"movie_id"`
	Title         string     `json:"title"`
	Genres        []string   `json:"genres"`
	Actors        []string   `json:"actors"`
	Directors     []string   `json:"directors"`
	Country       string     `json:"country"`
	ReleaseYear   int32      `json:"release_year"`
	IMDbRating    float32    `json:"imdb_rating"`
	Source        string     `json:"source"`
	SourceMovieID string     `json:"source_movie_id"`
	LastSyncAt    time.Time  `json:"last_sync_at"`
	ArchivedAt    *time.Time `json:"archived_at,omitempty"`
}

func (m Movie) Validate() error {
	if m.MovieID != uuid.Nil {
		if _, err := m.MovieID.Value(); err != nil {
			return ErrInvalidMovie
		}
	}
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
	return nil
}
