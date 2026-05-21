package movieservice

import (
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	moviev1 "github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"

	"github.com/google/uuid"
)

// --- protoToSnapshot ---

func TestProtoToSnapshot_NilMovie_ReturnsError(t *testing.T) {
	_, err := protoToSnapshot(nil)
	if err == nil {
		t.Fatal("expected error for nil movie")
	}
}

func TestProtoToSnapshot_InvalidMovieID_ReturnsError(t *testing.T) {
	_, err := protoToSnapshot(&moviev1.Movie{
		MovieId: "not-a-uuid",
	})
	if err == nil {
		t.Fatal("expected error for invalid movie_id")
	}
}

func TestProtoToSnapshot_ValidMovie_MapsAllFields(t *testing.T) {
	movieID := uuid.New()
	genreID := uuid.New()
	actorID := uuid.New()
	directorID := uuid.New()

	proto := &moviev1.Movie{
		MovieId:     movieID.String(),
		Title:       "Inception",
		Description: "Dream within a dream",
		Genres:      []*moviev1.Genre{{Id: genreID.String(), Name: "Sci-Fi"}},
		Actors:      []*moviev1.Person{{Id: actorID.String(), Name: "Leo", Surname: "D"}},
		Directors:   []*moviev1.Person{{Id: directorID.String(), Name: "Chris", Surname: "N"}},
		Country:     "US",
		ReleaseYear: 2010,
		ImdbRating:  8.8,
	}

	snap, err := protoToSnapshot(proto)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.MovieID != movieID {
		t.Errorf("MovieID mismatch")
	}
	if snap.Title != "Inception" {
		t.Errorf("Title mismatch")
	}
	if snap.Description != "Dream within a dream" {
		t.Errorf("Description mismatch")
	}
	if snap.Country != "US" {
		t.Errorf("Country mismatch")
	}
	if snap.ReleaseYear != 2010 {
		t.Errorf("ReleaseYear mismatch")
	}
	if snap.IMDbRating != 8.8 {
		t.Errorf("IMDbRating mismatch")
	}
	if len(snap.Genres) != 1 || snap.Genres[0].ID != genreID {
		t.Error("genres not mapped correctly")
	}
	if len(snap.Actors) != 1 || snap.Actors[0].ID != actorID {
		t.Error("actors not mapped correctly")
	}
	if len(snap.Directors) != 1 || snap.Directors[0].ID != directorID {
		t.Error("directors not mapped correctly")
	}
}

// --- protoToGenres ---

func TestProtoToGenres_InvalidID_ReturnsError(t *testing.T) {
	_, err := protoToGenres([]*moviev1.Genre{{Id: "bad-id", Name: "Action"}})
	if err == nil {
		t.Fatal("expected error for invalid genre ID")
	}
}

func TestProtoToGenres_ValidGenres_MapsCorrectly(t *testing.T) {
	id := uuid.New()
	genres, err := protoToGenres([]*moviev1.Genre{{Id: id.String(), Name: "Drama"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(genres) != 1 {
		t.Fatalf("expected 1 genre, got %d", len(genres))
	}
	if genres[0].ID != id || genres[0].Name != "Drama" {
		t.Error("genre fields not mapped correctly")
	}
}

func TestProtoToGenres_EmptySlice_ReturnsEmpty(t *testing.T) {
	genres, err := protoToGenres(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(genres) != 0 {
		t.Errorf("expected 0 genres, got %d", len(genres))
	}
}

// --- protoToPersons ---

func TestProtoToPersons_InvalidID_ReturnsError(t *testing.T) {
	_, err := protoToPersons([]*moviev1.Person{{Id: "not-uuid", Name: "A", Surname: "B"}})
	if err == nil {
		t.Fatal("expected error for invalid person ID")
	}
}

func TestProtoToPersons_WithBirthYear_MapsCorrectly(t *testing.T) {
	id := uuid.New()
	birthYear := int32(1970)
	persons, err := protoToPersons([]*moviev1.Person{{
		Id:        id.String(),
		Name:      "John",
		Surname:   "Doe",
		BirthYear: &birthYear,
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if persons[0].BirthYear != 1970 {
		t.Errorf("BirthYear mismatch: expected 1970, got %d", persons[0].BirthYear)
	}
}

func TestProtoToPersons_WithoutBirthYear_DefaultsToZero(t *testing.T) {
	id := uuid.New()
	persons, err := protoToPersons([]*moviev1.Person{{
		Id: id.String(), Name: "Jane", Surname: "Smith",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if persons[0].BirthYear != 0 {
		t.Errorf("expected zero BirthYear, got %d", persons[0].BirthYear)
	}
}

func TestProtoToPersons_ValidPerson_MapsAllFields(t *testing.T) {
	id := uuid.New()
	persons, err := protoToPersons([]*moviev1.Person{{
		Id: id.String(), Name: "Alice", Surname: "Wonder",
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if persons[0].ID != id || persons[0].Name != "Alice" || persons[0].Surname != "Wonder" {
		t.Error("person fields not mapped correctly")
	}
}

// --- filterToProto ---

func TestFilterToProto_EmptyFilter_ProducesEmptyRequest(t *testing.T) {
	req := filterToProto(ports.MovieFilter{})
	if req.Query != "" || req.Country != nil || req.Limit != 0 {
		t.Error("empty filter should produce empty proto request")
	}
	if len(req.Genres) != 0 || len(req.Actors) != 0 || len(req.Directors) != 0 {
		t.Error("empty filter should have no genres/actors/directors")
	}
}

func ptrString(s string) *string    { return &s }
func ptrInt32(i int32) *int32       { return &i }
func ptrFloat32(f float32) *float32 { return &f }

func TestFilterToProto_AllScalarFieldsMapped(t *testing.T) {
	country := "UK"
	yearFrom := int32(2000)
	yearTo := int32(2020)
	ratingFrom := float32(7.0)
	ratingTo := float32(9.5)
	f := ports.MovieFilter{
		Query:           "thriller",
		Country:         &country,
		ReleaseYearFrom: &yearFrom,
		ReleaseYearTo:   &yearTo,
		IMDbRatingFrom:  &ratingFrom,
		IMDbRatingTo:    &ratingTo,
		Limit:           25,
		Offset:          50,
		SortBy:          "imdb_rating",
		SortOrder:       "desc",
		IncludeArchived: true,
	}

	req := filterToProto(f)

	if req.Query != "thriller" {
		t.Errorf("Query mismatch: %q", req.Query)
	}
	if req.Country == nil || *req.Country != "UK" {
		t.Errorf("Country mismatch: %v", req.Country)
	}
	if req.ReleaseYearFrom == nil || *req.ReleaseYearFrom != 2000 {
		t.Error("ReleaseYearFrom mismatch")
	}
	if req.ReleaseYearTo == nil || *req.ReleaseYearTo != 2020 {
		t.Error("ReleaseYearTo mismatch")
	}
	if req.ImdbRatingFrom == nil || *req.ImdbRatingFrom != 7.0 {
		t.Error("ImdbRatingFrom mismatch")
	}
	if req.ImdbRatingTo == nil || *req.ImdbRatingTo != 9.5 {
		t.Error("ImdbRatingTo mismatch")
	}
	if req.Limit != 25 || req.Offset != 50 {
		t.Errorf("pagination mismatch: limit=%d offset=%d", req.Limit, req.Offset)
	}
	if req.SortBy != "imdb_rating" || req.SortOrder != "desc" {
		t.Error("sort fields mismatch")
	}
	if !req.IncludeArchived {
		t.Error("IncludeArchived mismatch")
	}
}

func TestFilterToProto_GenresMapped(t *testing.T) {
	genreID := uuid.New()
	f := ports.MovieFilter{
		Genres: []domain.Genre{{ID: genreID, Name: "Action"}},
	}
	req := filterToProto(f)

	if len(req.Genres) != 1 {
		t.Fatalf("expected 1 genre, got %d", len(req.Genres))
	}
	if req.Genres[0].Id != genreID.String() || req.Genres[0].Name != "Action" {
		t.Error("genre not mapped correctly")
	}
}

func TestFilterToProto_ActorsMapped(t *testing.T) {
	actorID := uuid.New()
	f := ports.MovieFilter{
		Actors: []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
	}
	req := filterToProto(f)

	if len(req.Actors) != 1 {
		t.Fatalf("expected 1 actor, got %d", len(req.Actors))
	}
	if req.Actors[0].Id != actorID.String() {
		t.Error("actor ID not mapped")
	}
	if req.Actors[0].Name != "John" || req.Actors[0].Surname != "Doe" {
		t.Error("actor name/surname not mapped")
	}
}

func TestFilterToProto_DirectorsMapped(t *testing.T) {
	directorID := uuid.New()
	f := ports.MovieFilter{
		Directors: []domain.Person{{ID: directorID, Name: "Jane", Surname: "Smith"}},
	}
	req := filterToProto(f)

	if len(req.Directors) != 1 {
		t.Fatalf("expected 1 director, got %d", len(req.Directors))
	}
	if req.Directors[0].Id != directorID.String() {
		t.Error("director ID not mapped")
	}
}

// --- domainPersonToProto ---

func TestDomainPersonToProto_WithBirthYear_SetsBirthYearPointer(t *testing.T) {
	p := domain.Person{ID: uuid.New(), Name: "A", Surname: "B", BirthYear: 1985}
	proto := domainPersonToProto(p)
	if proto.BirthYear == nil {
		t.Fatal("expected non-nil BirthYear pointer")
	}
	if *proto.BirthYear != 1985 {
		t.Errorf("expected 1985, got %d", *proto.BirthYear)
	}
}

func TestDomainPersonToProto_ZeroBirthYear_LeavesPointerNil(t *testing.T) {
	p := domain.Person{ID: uuid.New(), Name: "A", Surname: "B", BirthYear: 0}
	proto := domainPersonToProto(p)
	if proto.BirthYear != nil {
		t.Error("zero BirthYear should produce nil pointer in proto")
	}
}

func TestDomainPersonToProto_MapsIDNameSurname(t *testing.T) {
	id := uuid.New()
	p := domain.Person{ID: id, Name: "Chris", Surname: "Evans"}
	proto := domainPersonToProto(p)
	if proto.Id != id.String() {
		t.Errorf("ID mismatch: expected %s, got %s", id, proto.Id)
	}
	if proto.Name != "Chris" || proto.Surname != "Evans" {
		t.Error("name/surname not mapped")
	}
}
