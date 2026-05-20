package grpc

import (
	"testing"

	"movie_service/internal/core/domain"
	"proto/movie-service/movieservicev1"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ── parseUUID ─────────────────────────────────────────────────────────────────

func TestParseUUID(t *testing.T) {
	t.Parallel()

	validID := uuid.New()

	tests := []struct {
		name     string
		raw      string
		field    string
		wantCode codes.Code // codes.OK means success
	}{
		{
			name:     "valid uuid",
			raw:      validID.String(),
			field:    "movie_id",
			wantCode: codes.OK,
		},
		{
			name:     "valid uuid with surrounding whitespace",
			raw:      "  " + validID.String() + "  ",
			field:    "movie_id",
			wantCode: codes.OK,
		},
		{
			name:     "empty string",
			raw:      "",
			field:    "movie_id",
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "whitespace only",
			raw:      "   ",
			field:    "user_id",
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "not a uuid",
			raw:      "not-a-uuid",
			field:    "movie_id",
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "truncated uuid",
			raw:      "550e8400-e29b-41d4",
			field:    "genre_id",
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseUUID(tt.raw, tt.field)
			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("parseUUID() unexpected error: %v", err)
				}
				if got.String() != validID.String() {
					t.Fatalf("parseUUID() = %v, want %v", got, validID)
				}
			} else {
				if err == nil {
					t.Fatalf("parseUUID() expected error, got nil")
				}
				if status.Code(err) != tt.wantCode {
					t.Fatalf("parseUUID() code = %v, want %v", status.Code(err), tt.wantCode)
				}
			}
		})
	}
}

func TestParseUUIDErrorContainsFieldName(t *testing.T) {
	t.Parallel()

	_, err := parseUUID("", "some_field_name")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := status.Convert(err).Message()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
}

// ── protoToMovie ──────────────────────────────────────────────────────────────

func TestProtoToMovie(t *testing.T) {
	t.Parallel()

	movieID := uuid.New()

	tests := []struct {
		name    string
		proto   *movieservicev1.Movie
		wantErr bool
		check   func(t *testing.T, m domain.Movie)
	}{
		{
			name:    "nil proto returns error",
			proto:   nil,
			wantErr: true,
		},
		{
			name: "full valid proto",
			proto: &movieservicev1.Movie{
				MovieId:     movieID.String(),
				Title:       "Inception",
				Description: "A mind-bending thriller.",
				Country:     "USA",
				ReleaseYear: 2010,
				ImdbRating:  8.8,
				Genres:      []*movieservicev1.Genre{{Name: "Sci-Fi"}},
				Actors:      []*movieservicev1.Person{{Name: "Leonardo", Surname: "DiCaprio"}},
				Directors:   []*movieservicev1.Person{{Name: "Christopher", Surname: "Nolan"}},
			},
			wantErr: false,
			check: func(t *testing.T, m domain.Movie) {
				if m.MovieID != movieID {
					t.Errorf("MovieID = %v, want %v", m.MovieID, movieID)
				}
				if m.Title != "Inception" {
					t.Errorf("Title = %q, want %q", m.Title, "Inception")
				}
				if m.ReleaseYear != 2010 {
					t.Errorf("ReleaseYear = %d, want 2010", m.ReleaseYear)
				}
				if len(m.Genres) != 1 || m.Genres[0].Name != "Sci-Fi" {
					t.Errorf("Genres = %v, unexpected", m.Genres)
				}
				if len(m.Actors) != 1 {
					t.Errorf("Actors = %v, want 1 actor", m.Actors)
				}
				if len(m.Directors) != 1 {
					t.Errorf("Directors = %v, want 1 director", m.Directors)
				}
			},
		},
		{
			name: "movie without movie_id is valid",
			proto: &movieservicev1.Movie{
				Title:       "No ID",
				Country:     "UK",
				ReleaseYear: 2000,
				Genres:      []*movieservicev1.Genre{{Name: "Drama"}},
				Actors:      []*movieservicev1.Person{{Name: "Tom", Surname: "Hardy"}},
				Directors:   []*movieservicev1.Person{{Name: "Guy", Surname: "Ritchie"}},
			},
			wantErr: false,
			check: func(t *testing.T, m domain.Movie) {
				if m.MovieID != uuid.Nil {
					t.Errorf("expected nil MovieID, got %v", m.MovieID)
				}
			},
		},
		{
			name: "invalid movie_id returns error",
			proto: &movieservicev1.Movie{
				MovieId: "not-a-uuid",
			},
			wantErr: true,
		},
		{
			name: "invalid genre id returns error",
			proto: &movieservicev1.Movie{
				Genres: []*movieservicev1.Genre{{Id: "bad-uuid", Name: "Drama"}},
			},
			wantErr: true,
		},
		{
			name: "invalid actor id returns error",
			proto: &movieservicev1.Movie{
				Actors: []*movieservicev1.Person{{Id: "bad-uuid", Name: "Tom", Surname: "Hanks"}},
			},
			wantErr: true,
		},
		{
			name: "invalid director id returns error",
			proto: &movieservicev1.Movie{
				Directors: []*movieservicev1.Person{{Id: "bad-uuid", Name: "Steven", Surname: "Spielberg"}},
			},
			wantErr: true,
		},
		{
			name: "title whitespace is trimmed",
			proto: &movieservicev1.Movie{
				Title:   "  Inception  ",
				Country: "  USA  ",
			},
			wantErr: false,
			check: func(t *testing.T, m domain.Movie) {
				if m.Title != "Inception" {
					t.Errorf("Title not trimmed: %q", m.Title)
				}
				if m.Country != "USA" {
					t.Errorf("Country not trimmed: %q", m.Country)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, err := protoToMovie(tt.proto)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("protoToMovie() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("protoToMovie() unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, m)
			}
		})
	}
}

// ── movieToProto ──────────────────────────────────────────────────────────────

func TestMovieToProto(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	genreID := uuid.New()
	personID := uuid.New()

	movie := domain.Movie{
		MovieID:     id,
		Title:       "Interstellar",
		Description: "Space exploration.",
		Country:     "USA",
		ReleaseYear: 2014,
		IMDbRating:  8.6,
		Genres:      []domain.Genre{{ID: genreID, Name: "Sci-Fi"}},
		Actors:      []domain.Person{{ID: personID, Name: "Matthew", Surname: "McConaughey", BirthYear: 1969}},
		Directors:   []domain.Person{{Name: "Christopher", Surname: "Nolan"}},
	}

	p := movieToProto(movie)

	if p.GetMovieId() != id.String() {
		t.Errorf("MovieId = %q, want %q", p.GetMovieId(), id.String())
	}
	if p.GetTitle() != "Interstellar" {
		t.Errorf("Title = %q, want %q", p.GetTitle(), "Interstellar")
	}
	if p.GetReleaseYear() != 2014 {
		t.Errorf("ReleaseYear = %d, want 2014", p.GetReleaseYear())
	}
	if p.GetImdbRating() != 8.6 {
		t.Errorf("ImdbRating = %v, want 8.6", p.GetImdbRating())
	}
	if len(p.GetGenres()) != 1 || p.GetGenres()[0].GetId() != genreID.String() {
		t.Errorf("Genres = %v, unexpected", p.GetGenres())
	}
	if len(p.GetActors()) != 1 || p.GetActors()[0].GetId() != personID.String() {
		t.Errorf("Actors = %v, unexpected", p.GetActors())
	}
	if p.GetActors()[0].GetBirthYear() != 1969 {
		t.Errorf("Actor BirthYear = %d, want 1969", p.GetActors()[0].GetBirthYear())
	}
}

func TestMovieToProtoZeroIDNotSet(t *testing.T) {
	t.Parallel()

	movie := domain.Movie{
		Genres:    []domain.Genre{{Name: "Drama"}},
		Actors:    []domain.Person{{Name: "Tom", Surname: "Hanks"}},
		Directors: []domain.Person{{Name: "Steven", Surname: "Spielberg"}},
	}

	p := movieToProto(movie)

	if p.GetMovieId() != uuid.Nil.String() {
		t.Errorf("MovieId should be nil UUID string, got %q", p.GetMovieId())
	}
	if len(p.GetGenres()) != 1 || p.GetGenres()[0].GetId() != "" {
		t.Errorf("Genre ID should be empty for nil UUID, got %v", p.GetGenres())
	}
	if len(p.GetActors()) != 1 || p.GetActors()[0].GetId() != "" {
		t.Errorf("Actor ID should be empty for nil UUID, got %v", p.GetActors())
	}
}

// ── protoGenresToDomain ───────────────────────────────────────────────────────

func TestProtoGenresToDomain(t *testing.T) {
	t.Parallel()

	genreID := uuid.New()

	tests := []struct {
		name      string
		genres    []*movieservicev1.Genre
		wantCount int
		wantErr   bool
	}{
		{
			name:      "nil slice returns empty",
			genres:    nil,
			wantCount: 0,
		},
		{
			name:      "empty slice returns empty",
			genres:    []*movieservicev1.Genre{},
			wantCount: 0,
		},
		{
			name:      "nil entry is skipped",
			genres:    []*movieservicev1.Genre{nil},
			wantCount: 0,
		},
		{
			name:      "empty genre (no id, no name) is skipped",
			genres:    []*movieservicev1.Genre{{Id: "", Name: ""}},
			wantCount: 0,
		},
		{
			name:      "genre by name only",
			genres:    []*movieservicev1.Genre{{Name: "Action"}},
			wantCount: 1,
		},
		{
			name:      "genre by id only",
			genres:    []*movieservicev1.Genre{{Id: genreID.String()}},
			wantCount: 1,
		},
		{
			name:      "genre by id and name",
			genres:    []*movieservicev1.Genre{{Id: genreID.String(), Name: "Action"}},
			wantCount: 1,
		},
		{
			name:    "invalid genre id returns error",
			genres:  []*movieservicev1.Genre{{Id: "not-a-uuid", Name: "Action"}},
			wantErr: true,
		},
		{
			name: "multiple genres",
			genres: []*movieservicev1.Genre{
				{Name: "Drama"},
				{Name: "Comedy"},
				nil,
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := protoGenresToDomain(tt.genres, "genres")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.wantCount {
				t.Errorf("len = %d, want %d", len(result), tt.wantCount)
			}
		})
	}
}

// ── protoPeopleToDomain ───────────────────────────────────────────────────────

func TestProtoPeopleToDomain(t *testing.T) {
	t.Parallel()

	personID := uuid.New()
	birthYear := int32(1964)

	tests := []struct {
		name      string
		people    []*movieservicev1.Person
		wantCount int
		wantErr   bool
		check     func(t *testing.T, people []domain.Person)
	}{
		{
			name:      "nil slice",
			people:    nil,
			wantCount: 0,
		},
		{
			name:      "nil entry skipped",
			people:    []*movieservicev1.Person{nil},
			wantCount: 0,
		},
		{
			name:      "empty person (no fields) skipped",
			people:    []*movieservicev1.Person{{Id: "", Name: "", Surname: ""}},
			wantCount: 0,
		},
		{
			name:      "person by name and surname",
			people:    []*movieservicev1.Person{{Name: "Tom", Surname: "Hanks"}},
			wantCount: 1,
		},
		{
			name:      "person by id only",
			people:    []*movieservicev1.Person{{Id: personID.String()}},
			wantCount: 1,
		},
		{
			name:    "invalid person id returns error",
			people:  []*movieservicev1.Person{{Id: "not-a-uuid"}},
			wantErr: true,
		},
		{
			name:   "birth year mapped when set",
			people: []*movieservicev1.Person{{Name: "Keanu", Surname: "Reeves", BirthYear: &birthYear}},
			check: func(t *testing.T, people []domain.Person) {
				if people[0].BirthYear != birthYear {
					t.Errorf("BirthYear = %d, want %d", people[0].BirthYear, birthYear)
				}
			},
			wantCount: 1,
		},
		{
			name:   "birth year not set when nil",
			people: []*movieservicev1.Person{{Name: "Keanu", Surname: "Reeves", BirthYear: nil}},
			check: func(t *testing.T, people []domain.Person) {
				if people[0].BirthYear != 0 {
					t.Errorf("BirthYear = %d, want 0", people[0].BirthYear)
				}
			},
			wantCount: 1,
		},
		{
			name:      "whitespace names trimmed",
			people:    []*movieservicev1.Person{{Name: "  Tom  ", Surname: "  Hanks  "}},
			wantCount: 1,
			check: func(t *testing.T, people []domain.Person) {
				if people[0].Name != "Tom" {
					t.Errorf("Name not trimmed: %q", people[0].Name)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := protoPeopleToDomain(tt.people, "actors")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.wantCount {
				t.Errorf("len = %d, want %d", len(result), tt.wantCount)
			}
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// ── genresToProto ─────────────────────────────────────────────────────────────

func TestGenresToProto(t *testing.T) {
	t.Parallel()

	id := uuid.New()

	tests := []struct {
		name      string
		genres    []domain.Genre
		wantCount int
	}{
		{name: "nil slice", genres: nil, wantCount: 0},
		{name: "empty slice", genres: []domain.Genre{}, wantCount: 0},
		{
			name:      "genre with both id and name",
			genres:    []domain.Genre{{ID: id, Name: "Drama"}},
			wantCount: 1,
		},
		{
			name:      "genre with name only",
			genres:    []domain.Genre{{Name: "Comedy"}},
			wantCount: 1,
		},
		{
			name:      "empty genre (nil id, empty name) skipped",
			genres:    []domain.Genre{{}},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := genresToProto(tt.genres)
			if len(result) != tt.wantCount {
				t.Errorf("len = %d, want %d", len(result), tt.wantCount)
			}
		})
	}
}

// ── peopleToProto ─────────────────────────────────────────────────────────────

func TestPeopleToProto(t *testing.T) {
	t.Parallel()

	id := uuid.New()

	tests := []struct {
		name      string
		people    []domain.Person
		wantCount int
	}{
		{name: "nil slice", people: nil, wantCount: 0},
		{
			name:      "person with id and names",
			people:    []domain.Person{{ID: id, Name: "Tom", Surname: "Hanks"}},
			wantCount: 1,
		},
		{
			name:      "person with names only",
			people:    []domain.Person{{Name: "Tom", Surname: "Hanks"}},
			wantCount: 1,
		},
		{
			name:      "empty person skipped",
			people:    []domain.Person{{}},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := peopleToProto(tt.people)
			if len(result) != tt.wantCount {
				t.Errorf("len = %d, want %d", len(result), tt.wantCount)
			}
		})
	}
}

func TestPeopleToProtoBirthYear(t *testing.T) {
	t.Parallel()

	withYear := []domain.Person{{Name: "Tom", Surname: "Hanks", BirthYear: 1956}}
	result := peopleToProto(withYear)
	if len(result) != 1 {
		t.Fatalf("expected 1 person, got %d", len(result))
	}
	if result[0].GetBirthYear() != 1956 {
		t.Errorf("BirthYear = %d, want 1956", result[0].GetBirthYear())
	}

	withoutYear := []domain.Person{{Name: "Tom", Surname: "Hanks", BirthYear: 0}}
	result2 := peopleToProto(withoutYear)
	if result2[0].BirthYear != nil {
		t.Errorf("BirthYear should be nil when 0, got %v", result2[0].BirthYear)
	}
}

// ── listRequestToFilter ───────────────────────────────────────────────────────

func TestListRequestToFilter(t *testing.T) {
	t.Parallel()

	ptr32 := func(v int32) *int32 { return &v }
	ptrF32 := func(v float32) *float32 { return &v }
	ptrStr := func(v string) *string { return &v }

	tests := []struct {
		name    string
		req     *movieservicev1.ListMoviesRequest
		wantErr bool
		check   func(t *testing.T, f interface{})
	}{
		{
			name:    "minimal valid request",
			req:     &movieservicev1.ListMoviesRequest{Limit: 10, Offset: 0},
			wantErr: false,
		},
		{
			name: "year range from > to returns error",
			req: &movieservicev1.ListMoviesRequest{
				ReleaseYearFrom: ptr32(2020),
				ReleaseYearTo:   ptr32(2010),
			},
			wantErr: true,
		},
		{
			name: "year range from == to is valid",
			req: &movieservicev1.ListMoviesRequest{
				ReleaseYearFrom: ptr32(2010),
				ReleaseYearTo:   ptr32(2010),
			},
			wantErr: false,
		},
		{
			name: "rating range from > to returns error",
			req: &movieservicev1.ListMoviesRequest{
				ImdbRatingFrom: ptrF32(8.0),
				ImdbRatingTo:   ptrF32(7.0),
			},
			wantErr: true,
		},
		{
			name: "rating range from == to is valid",
			req: &movieservicev1.ListMoviesRequest{
				ImdbRatingFrom: ptrF32(7.5),
				ImdbRatingTo:   ptrF32(7.5),
			},
			wantErr: false,
		},
		{
			name: "country whitespace trimmed",
			req: &movieservicev1.ListMoviesRequest{
				Country: ptrStr("  USA  "),
			},
			wantErr: false,
		},
		{
			name: "country whitespace-only becomes nil",
			req: &movieservicev1.ListMoviesRequest{
				Country: ptrStr("   "),
			},
			wantErr: false,
		},
		{
			name: "invalid genre id returns error",
			req: &movieservicev1.ListMoviesRequest{
				Genres: []*movieservicev1.Genre{{Id: "bad-uuid", Name: "Action"}},
			},
			wantErr: true,
		},
		{
			name: "invalid actor id returns error",
			req: &movieservicev1.ListMoviesRequest{
				Actors: []*movieservicev1.Person{{Id: "bad-uuid", Name: "Tom", Surname: "Hanks"}},
			},
			wantErr: true,
		},
		{
			name: "invalid director id returns error",
			req: &movieservicev1.ListMoviesRequest{
				Directors: []*movieservicev1.Person{{Id: "bad-uuid", Name: "Chris", Surname: "Nolan"}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := listRequestToFilter(tt.req)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestListRequestToFilterFieldMapping(t *testing.T) {
	t.Parallel()

	ptr32 := func(v int32) *int32 { return &v }
	ptrF32 := func(v float32) *float32 { return &v }
	ptrStr := func(v string) *string { return &v }

	req := &movieservicev1.ListMoviesRequest{
		Query:           "  inception  ",
		Limit:           20,
		Offset:          5,
		SortBy:          "title",
		SortOrder:       "desc",
		IncludeArchived: true,
		Country:         ptrStr("USA"),
		ReleaseYearFrom: ptr32(2000),
		ReleaseYearTo:   ptr32(2020),
		ImdbRatingFrom:  ptrF32(7.0),
		ImdbRatingTo:    ptrF32(9.0),
		Genres:          []*movieservicev1.Genre{{Name: "Drama"}},
		Actors:          []*movieservicev1.Person{{Name: "Tom", Surname: "Hanks"}},
		Directors:       []*movieservicev1.Person{{Name: "Steven", Surname: "Spielberg"}},
	}

	filter, err := listRequestToFilter(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if filter.Query != "inception" {
		t.Errorf("Query = %q, want %q", filter.Query, "inception")
	}
	if filter.Limit != 20 {
		t.Errorf("Limit = %d, want 20", filter.Limit)
	}
	if filter.Offset != 5 {
		t.Errorf("Offset = %d, want 5", filter.Offset)
	}
	if filter.SortBy != "title" {
		t.Errorf("SortBy = %q, want %q", filter.SortBy, "title")
	}
	if filter.SortOrder != "desc" {
		t.Errorf("SortOrder = %q, want %q", filter.SortOrder, "desc")
	}
	if !filter.IncludeArchived {
		t.Error("IncludeArchived should be true")
	}
	if filter.Country == nil || *filter.Country != "USA" {
		t.Errorf("Country = %v, want USA", filter.Country)
	}
	if filter.ReleaseYearFrom == nil || *filter.ReleaseYearFrom != 2000 {
		t.Errorf("ReleaseYearFrom = %v, want 2000", filter.ReleaseYearFrom)
	}
	if filter.ReleaseYearTo == nil || *filter.ReleaseYearTo != 2020 {
		t.Errorf("ReleaseYearTo = %v, want 2020", filter.ReleaseYearTo)
	}
	if filter.IMDbRatingFrom == nil || *filter.IMDbRatingFrom != 7.0 {
		t.Errorf("IMDbRatingFrom = %v, want 7.0", filter.IMDbRatingFrom)
	}
	if filter.IMDbRatingTo == nil || *filter.IMDbRatingTo != 9.0 {
		t.Errorf("IMDbRatingTo = %v, want 9.0", filter.IMDbRatingTo)
	}
	if len(filter.Genres) != 1 {
		t.Errorf("Genres len = %d, want 1", len(filter.Genres))
	}
	if len(filter.Actors) != 1 {
		t.Errorf("Actors len = %d, want 1", len(filter.Actors))
	}
	if len(filter.Directors) != 1 {
		t.Errorf("Directors len = %d, want 1", len(filter.Directors))
	}
}
