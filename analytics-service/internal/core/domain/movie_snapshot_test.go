package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func validSnapshot() MovieSnapshot {
	return MovieSnapshot{
		MovieID:     uuid.New(),
		Title:       "Inception",
		Description: "A mind-bending thriller",
		Genres:      []Genre{{ID: uuid.New(), Name: "Sci-Fi"}},
		Actors:      []Person{{ID: uuid.New(), Name: "Leonardo", Surname: "DiCaprio"}},
		Directors:   []Person{{ID: uuid.New(), Name: "Christopher", Surname: "Nolan"}},
		Country:     "US",
		ReleaseYear: 2010,
		IMDbRating:  8.8,
	}
}

func TestMovieSnapshot_Validate_HappyPath(t *testing.T) {
	if err := validSnapshot().Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestMovieSnapshot_Validate_NilMovieID_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.MovieID = uuid.Nil
	if err := s.Validate(); err == nil {
		t.Error("expected error for nil MovieID")
	}
}

func TestMovieSnapshot_Validate_EmptyTitle_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Title = ""
	if err := s.Validate(); err == nil {
		t.Error("expected error for empty title")
	}
}

func TestMovieSnapshot_Validate_WhitespaceTitle_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Title = "   "
	if err := s.Validate(); err == nil {
		t.Error("expected error for whitespace-only title")
	}
}

func TestMovieSnapshot_Validate_EmptyDescription_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Description = ""
	if err := s.Validate(); err == nil {
		t.Error("expected error for empty description")
	}
}

func TestMovieSnapshot_Validate_EmptyCountry_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Country = ""
	if err := s.Validate(); err == nil {
		t.Error("expected error for empty country")
	}
}

func TestMovieSnapshot_Validate_NoGenres_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Genres = nil
	if err := s.Validate(); err == nil {
		t.Error("expected error for empty genres")
	}
}

func TestMovieSnapshot_Validate_NoActors_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Actors = nil
	if err := s.Validate(); err == nil {
		t.Error("expected error for empty actors")
	}
}

func TestMovieSnapshot_Validate_NoDirectors_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.Directors = nil
	if err := s.Validate(); err == nil {
		t.Error("expected error for empty directors")
	}
}

func TestMovieSnapshot_Validate_ReleaseYearBelowMin_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.ReleaseYear = 1887
	if err := s.Validate(); err == nil {
		t.Error("expected error for release year below 1888")
	}
}

func TestMovieSnapshot_Validate_MinReleaseYear_IsValid(t *testing.T) {
	s := validSnapshot()
	s.ReleaseYear = 1888
	if err := s.Validate(); err != nil {
		t.Errorf("1888 should be a valid release year, got %v", err)
	}
}

func TestMovieSnapshot_Validate_CurrentYearReleaseIsValid(t *testing.T) {
	s := validSnapshot()
	s.ReleaseYear = int32(time.Now().Year())
	if err := s.Validate(); err != nil {
		t.Errorf("current year should be valid, got %v", err)
	}
}

func TestMovieSnapshot_Validate_FutureReleaseYear_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.ReleaseYear = int32(time.Now().Year()) + 1
	if err := s.Validate(); err == nil {
		t.Error("expected error for future release year")
	}
}

func TestMovieSnapshot_Validate_NegativeIMDbRating_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.IMDbRating = -0.1
	if err := s.Validate(); err == nil {
		t.Error("expected error for negative IMDb rating")
	}
}

func TestMovieSnapshot_Validate_IMDbRatingAbove10_ReturnsError(t *testing.T) {
	s := validSnapshot()
	s.IMDbRating = 10.1
	if err := s.Validate(); err == nil {
		t.Error("expected error for IMDb rating > 10")
	}
}

func TestMovieSnapshot_Validate_ZeroIMDbRating_IsValid(t *testing.T) {
	s := validSnapshot()
	s.IMDbRating = 0
	if err := s.Validate(); err != nil {
		t.Errorf("IMDb rating 0 should be valid, got %v", err)
	}
}

func TestMovieSnapshot_Validate_ReturnsCorrectSentinel(t *testing.T) {
	s := validSnapshot()
	s.MovieID = uuid.Nil
	if err := s.Validate(); err != ErrInvalidMovieSnapshot {
		t.Errorf("expected ErrInvalidMovieSnapshot, got %v", err)
	}
}
