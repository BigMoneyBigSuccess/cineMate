package syncer

import (
	"testing"
)

// ── parsePerson ───────────────────────────────────────────────────────────────

func TestParsePersonPrefersEnglishName(t *testing.T) {
	t.Parallel()

	person, ok := parsePerson(StaffMember{NameEn: "Tom Hanks", NameRu: "Том Хэнкс"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if person.Name != "Tom" || person.Surname != "Hanks" {
		t.Errorf("Name=%q Surname=%q, want Tom Hanks", person.Name, person.Surname)
	}
}

func TestParsePersonFallsBackToRussianName(t *testing.T) {
	t.Parallel()

	person, ok := parsePerson(StaffMember{NameEn: "", NameRu: "Андрей Тарковский"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if person.Name != "Андрей" || person.Surname != "Тарковский" {
		t.Errorf("Name=%q Surname=%q, want Андрей Тарковский", person.Name, person.Surname)
	}
}

func TestParsePersonBothNamesEmptyReturnsFalse(t *testing.T) {
	t.Parallel()

	_, ok := parsePerson(StaffMember{NameEn: "", NameRu: ""})
	if ok {
		t.Fatal("expected ok=false for empty names")
	}
}

func TestParsePersonWhitespaceOnlyReturnsFalse(t *testing.T) {
	t.Parallel()

	_, ok := parsePerson(StaffMember{NameEn: "   ", NameRu: "  "})
	if ok {
		t.Fatal("expected ok=false for whitespace-only names")
	}
}

func TestParsePersonSingleTokenUsesBothFields(t *testing.T) {
	t.Parallel()

	person, ok := parsePerson(StaffMember{NameEn: "Spielberg"})
	if !ok {
		t.Fatal("expected ok=true for single-token name")
	}
	if person.Name != "Spielberg" || person.Surname != "Spielberg" {
		t.Errorf("Name=%q Surname=%q, want Spielberg/Spielberg", person.Name, person.Surname)
	}
}

func TestParsePersonTrimsWhitespace(t *testing.T) {
	t.Parallel()

	person, ok := parsePerson(StaffMember{NameEn: "  Tom   Hanks  "})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if person.Name != "Tom" || person.Surname != "Hanks" {
		t.Errorf("Name=%q Surname=%q, want Tom Hanks", person.Name, person.Surname)
	}
}

func TestParsePersonSplitsOnFirstSpaceOnly(t *testing.T) {
	t.Parallel()

	// "Jean-Claude Van Damme" → Name="Jean-Claude", Surname="Van Damme"
	person, ok := parsePerson(StaffMember{NameEn: "Jean-Claude Van Damme"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if person.Name != "Jean-Claude" || person.Surname != "Van Damme" {
		t.Errorf("Name=%q Surname=%q, want Jean-Claude / Van Damme", person.Name, person.Surname)
	}
}

func TestParsePersonEnglishPreferredOverRussianEvenWhenRussianPresent(t *testing.T) {
	t.Parallel()

	person, ok := parsePerson(StaffMember{NameEn: "Christopher Nolan", NameRu: "Кристофер Нолан"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if person.Name != "Christopher" {
		t.Errorf("expected English name, got %q", person.Name)
	}
}

// ── mapFilmToMovie ────────────────────────────────────────────────────────────

func newFilmItem(kinopoiskID int, nameRu string) FilmItem {
	return FilmItem{
		KinopoiskID: kinopoiskID,
		NameRu:      nameRu,
		Countries:   []CountryDTO{{Country: "Russia"}},
		Genres:      []GenreDTO{{Genre: "Drama"}},
	}
}

func TestMapFilmToMovieUsesOriginalNameWhenSet(t *testing.T) {
	t.Parallel()

	original := "Stalker"
	item := newFilmItem(12345, "Сталкер")
	item.NameOriginal = &original

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.Title != "Stalker" {
		t.Errorf("Title = %q, want %q", movie.Title, "Stalker")
	}
}

func TestMapFilmToMovieFallsBackToRussianTitle(t *testing.T) {
	t.Parallel()

	item := newFilmItem(12345, "Сталкер")
	item.NameOriginal = nil

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.Title != "Сталкер" {
		t.Errorf("Title = %q, want %q", movie.Title, "Сталкер")
	}
}

func TestMapFilmToMovieIgnoresEmptyOriginalName(t *testing.T) {
	t.Parallel()

	empty := "  "
	item := newFilmItem(12345, "Сталкер")
	item.NameOriginal = &empty

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.Title != "Сталкер" {
		t.Errorf("Title = %q, want Russian title when OriginalName is whitespace", movie.Title)
	}
}

func TestMapFilmToMovieSetsSourceAndSourceMovieID(t *testing.T) {
	t.Parallel()

	item := newFilmItem(99999, "Film")
	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.Source != Source {
		t.Errorf("Source = %q, want %q", movie.Source, Source)
	}
	if movie.SourceMovieID != "99999" {
		t.Errorf("SourceMovieID = %q, want %q", movie.SourceMovieID, "99999")
	}
}

func TestMapFilmToMovieExtractsCountry(t *testing.T) {
	t.Parallel()

	item := newFilmItem(1, "Film")
	item.Countries = []CountryDTO{{Country: "France"}, {Country: "Germany"}}

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.Country != "France" {
		t.Errorf("Country = %q, want %q (first country)", movie.Country, "France")
	}
}

func TestMapFilmToMovieNoCountryIsEmpty(t *testing.T) {
	t.Parallel()

	item := newFilmItem(1, "Film")
	item.Countries = nil

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.Country != "" {
		t.Errorf("Country = %q, want empty when no countries", movie.Country)
	}
}

func TestMapFilmToMovieSetsReleaseYear(t *testing.T) {
	t.Parallel()

	year := 1979
	item := newFilmItem(1, "Film")
	item.Year = &year

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.ReleaseYear != 1979 {
		t.Errorf("ReleaseYear = %d, want 1979", movie.ReleaseYear)
	}
}

func TestMapFilmToMovieZeroReleaseYearWhenNil(t *testing.T) {
	t.Parallel()

	item := newFilmItem(1, "Film")
	item.Year = nil

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.ReleaseYear != 0 {
		t.Errorf("ReleaseYear = %d, want 0 when year is nil", movie.ReleaseYear)
	}
}

func TestMapFilmToMovieSetsIMDbRating(t *testing.T) {
	t.Parallel()

	rating := float32(8.4)
	item := newFilmItem(1, "Film")
	item.RatingImdb = &rating

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if movie.IMDbRating != 8.4 {
		t.Errorf("IMDbRating = %v, want 8.4", movie.IMDbRating)
	}
}

func TestMapFilmToMovieExtractsGenres(t *testing.T) {
	t.Parallel()

	item := newFilmItem(1, "Film")
	item.Genres = []GenreDTO{{Genre: "Action"}, {Genre: "  "}, {Genre: "Comedy"}}

	movie := mapFilmToMovie(item, nil, []StaffMember{})

	if len(movie.Genres) != 2 {
		t.Errorf("Genres len = %d, want 2 (whitespace-only genre should be skipped)", len(movie.Genres))
	}
}

func TestMapFilmToMovieSetsDescriptionFromDetail(t *testing.T) {
	t.Parallel()

	desc := "A mysterious zone."
	item := newFilmItem(1, "Film")
	detail := &FilmDetail{Description: &desc}

	movie := mapFilmToMovie(item, detail, []StaffMember{})

	if movie.Description != "A mysterious zone." {
		t.Errorf("Description = %q, want %q", movie.Description, "A mysterious zone.")
	}
}

func TestMapFilmToMovieNoDescriptionWhenDetailNil(t *testing.T) {
	t.Parallel()

	movie := mapFilmToMovie(newFilmItem(1, "Film"), nil, []StaffMember{})

	if movie.Description != "" {
		t.Errorf("Description = %q, want empty when detail is nil", movie.Description)
	}
}

func TestMapFilmToMovieSeparatesActorsAndDirectors(t *testing.T) {
	t.Parallel()

	staff := []StaffMember{
		{NameEn: "Steven Spielberg", ProfessionKey: "DIRECTOR"},
		{NameEn: "Tom Hanks", ProfessionKey: "ACTOR"},
		{NameEn: "John Williams", ProfessionKey: "COMPOSER"},
	}

	movie := mapFilmToMovie(newFilmItem(1, "Film"), nil, staff)

	if len(movie.Directors) != 1 || movie.Directors[0].Name != "Steven" {
		t.Errorf("Directors = %v, want [{Steven Spielberg}]", movie.Directors)
	}
	if len(movie.Actors) != 1 || movie.Actors[0].Name != "Tom" {
		t.Errorf("Actors = %v, want [{Tom Hanks}]", movie.Actors)
	}
}

func TestMapFilmToMovieCapsActorsAtMaxActors(t *testing.T) {
	t.Parallel()

	staff := make([]StaffMember, maxActors+5)
	for i := range staff {
		staff[i] = StaffMember{
			NameEn:        "Actor Name",
			ProfessionKey: "ACTOR",
		}
	}

	movie := mapFilmToMovie(newFilmItem(1, "Film"), nil, staff)

	if len(movie.Actors) != maxActors {
		t.Errorf("Actors len = %d, want %d (max cap)", len(movie.Actors), maxActors)
	}
}

func TestMapFilmToMovieDirectorsNotCapped(t *testing.T) {
	t.Parallel()

	staff := make([]StaffMember, maxActors+5)
	for i := range staff {
		staff[i] = StaffMember{
			NameEn:        "Director Name",
			ProfessionKey: "DIRECTOR",
		}
	}

	movie := mapFilmToMovie(newFilmItem(1, "Film"), nil, staff)

	if len(movie.Directors) != maxActors+5 {
		t.Errorf("Directors len = %d, want %d (no cap)", len(movie.Directors), maxActors+5)
	}
}

func TestMapFilmToMovieSkipsStaffWithEmptyName(t *testing.T) {
	t.Parallel()

	staff := []StaffMember{
		{NameEn: "", NameRu: "", ProfessionKey: "ACTOR"},
		{NameEn: "Tom Hanks", ProfessionKey: "ACTOR"},
	}

	movie := mapFilmToMovie(newFilmItem(1, "Film"), nil, staff)

	if len(movie.Actors) != 1 {
		t.Errorf("Actors len = %d, want 1 (empty name should be skipped)", len(movie.Actors))
	}
}
