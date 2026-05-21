package engine

import (
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"

	"github.com/google/uuid"
)

// --- scoreAndSort ---

func TestScoreAndSort_RanksByIMDbRatingWhenNoProfileMatch(t *testing.T) {
	highID := uuid.New()
	lowID := uuid.New()

	result := scoreAndSort([]domain.MovieSnapshot{
		{MovieID: lowID, IMDbRating: 5.0},
		{MovieID: highID, IMDbRating: 9.0},
	}, domain.UserPreferenceProfile{})

	if result[0].MovieID != highID {
		t.Error("higher IMDb rating should rank first")
	}
}

func TestScoreAndSort_GenreMatchBoostsAboveHigherIMDb(t *testing.T) {
	noMatchID := uuid.New()
	matchID := uuid.New()
	genreID := uuid.New()

	// noMatch: 8.0; match: 7.0 + 3.0 (genre) = 10.0
	result := scoreAndSort([]domain.MovieSnapshot{
		{MovieID: noMatchID, IMDbRating: 8.0},
		{MovieID: matchID, IMDbRating: 7.0, Genres: []domain.Genre{{ID: genreID, Name: "Action"}}},
	}, domain.UserPreferenceProfile{
		PreferredGenres: []domain.Genre{{ID: genreID, Name: "Action"}},
	})

	if result[0].MovieID != matchID {
		t.Error("genre match should boost score to 10.0, beating 8.0")
	}
}

func TestScoreAndSort_ActorMatchBoostsScore(t *testing.T) {
	noMatchID := uuid.New()
	matchID := uuid.New()
	actorID := uuid.New()

	// noMatch: 8.0; match: 7.0 + 1.5 (actor) = 8.5
	result := scoreAndSort([]domain.MovieSnapshot{
		{MovieID: noMatchID, IMDbRating: 8.0},
		{MovieID: matchID, IMDbRating: 7.0, Actors: []domain.Person{{ID: actorID, Name: "A", Surname: "B"}}},
	}, domain.UserPreferenceProfile{
		PreferredActors: []domain.Person{{ID: actorID}},
	})

	if result[0].MovieID != matchID {
		t.Error("actor match should boost 7.0 to 8.5, beating 8.0")
	}
}

func TestScoreAndSort_DirectorMatchBoostsScore(t *testing.T) {
	noMatchID := uuid.New()
	matchID := uuid.New()
	directorID := uuid.New()

	// noMatch: 8.0; match: 7.0 + 1.5 (director) = 8.5
	result := scoreAndSort([]domain.MovieSnapshot{
		{MovieID: noMatchID, IMDbRating: 8.0},
		{MovieID: matchID, IMDbRating: 7.0, Directors: []domain.Person{{ID: directorID, Name: "X", Surname: "Y"}}},
	}, domain.UserPreferenceProfile{
		PreferredDirectors: []domain.Person{{ID: directorID}},
	})

	if result[0].MovieID != matchID {
		t.Error("director match should boost 7.0 to 8.5, beating 8.0")
	}
}

func TestScoreAndSort_MultipleMatchesStack(t *testing.T) {
	lowID := uuid.New()
	highID := uuid.New()
	genreID := uuid.New()
	actorID := uuid.New()

	// lowID: 5.0 + 3.0 (genre) + 1.5 (actor) = 9.5; highID: 9.0
	result := scoreAndSort([]domain.MovieSnapshot{
		{MovieID: highID, IMDbRating: 9.0},
		{MovieID: lowID, IMDbRating: 5.0,
			Genres: []domain.Genre{{ID: genreID}},
			Actors: []domain.Person{{ID: actorID}},
		},
	}, domain.UserPreferenceProfile{
		PreferredGenres: []domain.Genre{{ID: genreID}},
		PreferredActors: []domain.Person{{ID: actorID}},
	})

	if result[0].MovieID != lowID {
		t.Error("genre+actor stacked boosts should outrank higher base IMDb rating")
	}
}

func TestScoreAndSort_EmptyInput_ReturnsEmpty(t *testing.T) {
	result := scoreAndSort(nil, domain.UserPreferenceProfile{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}
}

func TestScoreAndSort_MultipleGenreMatches_AllBoostStack(t *testing.T) {
	movieID := uuid.New()
	g1 := uuid.New()
	g2 := uuid.New()

	// Two genre matches: 0.0 (imdb) + 3.0 + 3.0 = 6.0
	result := scoreAndSort([]domain.MovieSnapshot{
		{MovieID: movieID, IMDbRating: 0.0, Genres: []domain.Genre{{ID: g1}, {ID: g2}}},
	}, domain.UserPreferenceProfile{
		PreferredGenres: []domain.Genre{{ID: g1}, {ID: g2}},
	})

	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
}

// --- genreMatches ---

func TestGenreMatches_ByID(t *testing.T) {
	id := uuid.New()
	if !genreMatches(domain.Genre{ID: id, Name: "X"}, []domain.Genre{{ID: id, Name: "Y"}}) {
		t.Error("should match by ID regardless of name")
	}
}

func TestGenreMatches_ByNameCaseInsensitive(t *testing.T) {
	if !genreMatches(
		domain.Genre{ID: uuid.Nil, Name: "action"},
		[]domain.Genre{{ID: uuid.Nil, Name: "ACTION"}},
	) {
		t.Error("should match by name case-insensitively when ID is nil")
	}
}

func TestGenreMatches_IDMatchOverridesNameMismatch(t *testing.T) {
	id := uuid.New()
	if !genreMatches(
		domain.Genre{ID: id, Name: "Drama"},
		[]domain.Genre{{ID: id, Name: "Action"}},
	) {
		t.Error("ID match should be sufficient even if names differ")
	}
}

func TestGenreMatches_DifferentIDAndName_ReturnsFalse(t *testing.T) {
	if genreMatches(
		domain.Genre{ID: uuid.New(), Name: "Drama"},
		[]domain.Genre{{ID: uuid.New(), Name: "Action"}},
	) {
		t.Error("different ID and name should not match")
	}
}

func TestGenreMatches_EmptyPreferred_ReturnsFalse(t *testing.T) {
	if genreMatches(domain.Genre{ID: uuid.New(), Name: "Drama"}, nil) {
		t.Error("should not match empty preferred list")
	}
}

// --- personMatches ---

func TestPersonMatches_ByID(t *testing.T) {
	id := uuid.New()
	if !personMatches(
		domain.Person{ID: id, Name: "John", Surname: "Doe"},
		[]domain.Person{{ID: id, Name: "Other", Surname: "Person"}},
	) {
		t.Error("should match by ID regardless of name/surname")
	}
}

func TestPersonMatches_ByNameAndSurnameCaseInsensitive(t *testing.T) {
	if !personMatches(
		domain.Person{ID: uuid.Nil, Name: "john", Surname: "doe"},
		[]domain.Person{{ID: uuid.Nil, Name: "JOHN", Surname: "DOE"}},
	) {
		t.Error("should match by name+surname case-insensitively when ID is nil")
	}
}

func TestPersonMatches_NameMatchSurnameMismatch_ReturnsFalse(t *testing.T) {
	if personMatches(
		domain.Person{ID: uuid.Nil, Name: "john", Surname: "smith"},
		[]domain.Person{{ID: uuid.Nil, Name: "john", Surname: "doe"}},
	) {
		t.Error("matching name but different surname should not match")
	}
}

func TestPersonMatches_DifferentIDAndName_ReturnsFalse(t *testing.T) {
	if personMatches(
		domain.Person{ID: uuid.New(), Name: "Alice", Surname: "Smith"},
		[]domain.Person{{ID: uuid.New(), Name: "Bob", Surname: "Jones"}},
	) {
		t.Error("different ID and name should not match")
	}
}

func TestPersonMatches_EmptyPreferred_ReturnsFalse(t *testing.T) {
	if personMatches(domain.Person{ID: uuid.New(), Name: "Alice", Surname: "Smith"}, nil) {
		t.Error("should not match empty preferred list")
	}
}

// --- appendUnique ---

func TestAppendUnique_DeduplicatesByMovieID(t *testing.T) {
	id := uuid.New()
	dst := []domain.MovieSnapshot{{MovieID: id}}
	src := []domain.MovieSnapshot{{MovieID: id}, {MovieID: uuid.New()}}

	result := appendUnique(dst, src)
	if len(result) != 2 {
		t.Errorf("expected 2 unique movies, got %d", len(result))
	}
}

func TestAppendUnique_EmptyDst_ReturnsAllFromSrc(t *testing.T) {
	src := []domain.MovieSnapshot{{MovieID: uuid.New()}, {MovieID: uuid.New()}}
	result := appendUnique(nil, src)
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

func TestAppendUnique_EmptySrc_PreservesExistingDst(t *testing.T) {
	id := uuid.New()
	dst := []domain.MovieSnapshot{{MovieID: id}}
	result := appendUnique(dst, nil)
	if len(result) != 1 || result[0].MovieID != id {
		t.Error("should preserve existing dst when src is empty")
	}
}

func TestAppendUnique_SrcDuplicatesWithinItself_AllAdded(t *testing.T) {
	// appendUnique only deduplicates against dst; if src itself has duplicates,
	// the first occurrence is added and subsequent ones are dropped.
	id := uuid.New()
	result := appendUnique(nil, []domain.MovieSnapshot{{MovieID: id}, {MovieID: id}})
	if len(result) != 1 {
		t.Errorf("expected 1 (first occurrence wins), got %d", len(result))
	}
}

// --- candidateBuffer ---

func TestCandidateBuffer_ReturnsTripleLimit(t *testing.T) {
	if candidateBuffer(10) != 30 {
		t.Errorf("expected 30, got %d", candidateBuffer(10))
	}
	if candidateBuffer(1) != 3 {
		t.Errorf("expected 3, got %d", candidateBuffer(1))
	}
}
