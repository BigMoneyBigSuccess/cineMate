package domain

import "testing"

func TestMovieValidateAllowsGeneratedMovieID(t *testing.T) {
	t.Parallel()

	movie := Movie{
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

	if err := movie.Validate(); err != nil {
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
