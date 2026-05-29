package movieservice

import (
	"fmt"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	moviev1 "github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"

	"github.com/google/uuid"
)

func protoToSnapshot(m *moviev1.Movie) (*domain.MovieSnapshot, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil movie", domain.ErrInvalidMovieSnapshot)
	}

	id, err := uuid.Parse(m.GetMovieId())
	if err != nil {
		return nil, fmt.Errorf("parse movie_id %q: %w", m.GetMovieId(), err)
	}

	genres, err := protoToGenres(m.GetGenres())
	if err != nil {
		return nil, err
	}
	actors, err := protoToPersons(m.GetActors())
	if err != nil {
		return nil, err
	}
	directors, err := protoToPersons(m.GetDirectors())
	if err != nil {
		return nil, err
	}

	return &domain.MovieSnapshot{
		MovieID:     id,
		Title:       m.GetTitle(),
		Description: m.GetDescription(),
		Genres:      genres,
		Actors:      actors,
		Directors:   directors,
		Country:     m.GetCountry(),
		ReleaseYear: m.GetReleaseYear(),
		IMDbRating:  m.GetImdbRating(),
	}, nil
}

func protoToGenres(pg []*moviev1.Genre) ([]domain.Genre, error) {
	genres := make([]domain.Genre, len(pg))
	for i, g := range pg {
		id, err := uuid.Parse(g.GetId())
		if err != nil {
			return nil, fmt.Errorf("parse genre id %q: %w", g.GetId(), err)
		}
		genres[i] = domain.Genre{ID: id, Name: g.GetName()}
	}
	return genres, nil
}

func protoToPersons(pp []*moviev1.Person) ([]domain.Person, error) {
	persons := make([]domain.Person, len(pp))
	for i, p := range pp {
		id, err := uuid.Parse(p.GetId())
		if err != nil {
			return nil, fmt.Errorf("parse person id %q: %w", p.GetId(), err)
		}
		var birthYear int32
		if p.BirthYear != nil {
			birthYear = p.GetBirthYear()
		}
		persons[i] = domain.Person{
			ID:        id,
			Name:      p.GetName(),
			Surname:   p.GetSurname(),
			BirthYear: birthYear,
		}
	}
	return persons, nil
}

func filterToProto(f ports.MovieFilter) *moviev1.ListMoviesRequest {
	req := &moviev1.ListMoviesRequest{
		Query:           f.Query,
		Country:         f.Country,
		ReleaseYearFrom: f.ReleaseYearFrom,
		ReleaseYearTo:   f.ReleaseYearTo,
		ImdbRatingFrom:  f.IMDbRatingFrom,
		ImdbRatingTo:    f.IMDbRatingTo,
		Limit:           int32(f.Limit),
		Offset:          int32(f.Offset),
		SortBy:          f.SortBy,
		SortOrder:       f.SortOrder,
		IncludeArchived: f.IncludeArchived,
	}

	for _, g := range f.Genres {
		req.Genres = append(req.Genres, &moviev1.Genre{
			Id:   g.ID.String(),
			Name: g.Name,
		})
	}
	for _, p := range f.Actors {
		req.Actors = append(req.Actors, domainPersonToProto(p))
	}
	for _, p := range f.Directors {
		req.Directors = append(req.Directors, domainPersonToProto(p))
	}

	return req
}

func domainPersonToProto(p domain.Person) *moviev1.Person {
	proto := &moviev1.Person{
		Id:      p.ID.String(),
		Name:    p.Name,
		Surname: p.Surname,
	}
	if p.BirthYear != 0 {
		proto.BirthYear = &p.BirthYear
	}
	return proto
}
