package domain

import (
	"testing"
	"time"
)

func validMovie() Movie {
	return Movie{
		Title:         "Catch Me If You Can",
		Description:   "A biographical crime comedy-drama film.",
		Genres:        []Genre{{Name: "Drama"}},
		Actors:        []Person{{Name: "Leonardo", Surname: "DiCaprio"}},
		Directors:     []Person{{Name: "Steven", Surname: "Spielberg"}},
		Country:       "USA",
		ReleaseYear:   2002,
		IMDbRating:    8.1,
		Source:        "kinopoisk",
		SourceMovieID: "12345",
	}
}

func TestMovieValidateAllowsGeneratedMovieID(t *testing.T) {
	t.Parallel()

	if err := validMovie().Validate(); err != nil {
		t.Fatalf("expected movie to be valid without explicit movie_id, got %v", err)
	}
}

func TestMovieValidateRejectsEmptyStructuredValues(t *testing.T) {
	t.Parallel()

	movie := Movie{
		Title:         "Movie",
		Genres:        []Genre{{}},
		Actors:        []Person{{Name: "Tom", Surname: "Hanks"}},
		Directors:     []Person{{Name: "Robert", Surname: "Zemeckis"}},
		Country:       "USA",
		ReleaseYear:   1994,
		IMDbRating:    8.8,
		Source:        "imdb",
		SourceMovieID: "tt0109830",
	}

	if err := movie.Validate(); err != ErrInvalidMovie {
		t.Fatalf("expected ErrInvalidMovie, got %v", err)
	}
}

func TestMovieValidate(t *testing.T) {
	t.Parallel()

	currentYear := int32(time.Now().Year())

	tests := []struct {
		name    string
		mutate  func(m *Movie)
		wantErr error
	}{
		{
			name:    "valid movie",
			mutate:  func(m *Movie) {},
			wantErr: nil,
		},
		{
			name:    "empty title",
			mutate:  func(m *Movie) { m.Title = "" },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "whitespace-only title",
			mutate:  func(m *Movie) { m.Title = "   " },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "empty country",
			mutate:  func(m *Movie) { m.Country = "" },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "whitespace-only country",
			mutate:  func(m *Movie) { m.Country = "  " },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "empty source",
			mutate:  func(m *Movie) { m.Source = "" },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "whitespace-only source",
			mutate:  func(m *Movie) { m.Source = "  " },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "empty source_movie_id",
			mutate:  func(m *Movie) { m.SourceMovieID = "" },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "whitespace-only source_movie_id",
			mutate:  func(m *Movie) { m.SourceMovieID = "  " },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "no genres",
			mutate:  func(m *Movie) { m.Genres = nil },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "empty genres slice",
			mutate:  func(m *Movie) { m.Genres = []Genre{} },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "no actors",
			mutate:  func(m *Movie) { m.Actors = nil },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "no directors",
			mutate:  func(m *Movie) { m.Directors = nil },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "release year exactly 1888",
			mutate:  func(m *Movie) { m.ReleaseYear = 1888 },
			wantErr: nil,
		},
		{
			name:    "release year below minimum",
			mutate:  func(m *Movie) { m.ReleaseYear = 1887 },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "release year at current year",
			mutate:  func(m *Movie) { m.ReleaseYear = currentYear },
			wantErr: nil,
		},
		{
			name:    "release year above current year",
			mutate:  func(m *Movie) { m.ReleaseYear = currentYear + 1 },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "imdb rating zero is valid",
			mutate:  func(m *Movie) { m.IMDbRating = 0 },
			wantErr: nil,
		},
		{
			name:    "imdb rating exactly 10",
			mutate:  func(m *Movie) { m.IMDbRating = 10 },
			wantErr: nil,
		},
		{
			name:    "imdb rating negative",
			mutate:  func(m *Movie) { m.IMDbRating = -0.1 },
			wantErr: ErrInvalidMovie,
		},
		{
			name:    "imdb rating above 10",
			mutate:  func(m *Movie) { m.IMDbRating = 10.1 },
			wantErr: ErrInvalidMovie,
		},
		{
			name: "invalid genre in list propagates error",
			mutate: func(m *Movie) {
				m.Genres = []Genre{{}} // empty ID and name
			},
			wantErr: ErrInvalidMovie,
		},
		{
			name: "invalid actor in list propagates error",
			mutate: func(m *Movie) {
				m.Actors = []Person{{}} // nil ID and empty name/surname
			},
			wantErr: ErrInvalidMovie,
		},
		{
			name: "invalid director in list propagates error",
			mutate: func(m *Movie) {
				m.Directors = []Person{{}} // nil ID and empty name/surname
			},
			wantErr: ErrInvalidMovie,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := validMovie()
			tt.mutate(&m)
			err := m.Validate()
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
