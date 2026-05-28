package grpc

import (
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func listRequestToFilter(req *movieservicev1.ListMoviesRequest) (ports.MovieFilter, error) {
	filter := ports.MovieFilter{
		Query:           strings.TrimSpace(req.GetQuery()),
		Limit:           int(req.GetLimit()),
		Offset:          int(req.GetOffset()),
		SortBy:          req.GetSortBy(),
		SortOrder:       req.GetSortOrder(),
		IncludeArchived: req.GetIncludeArchived(),
	}

	if req.Country != nil {
		country := strings.TrimSpace(req.GetCountry())
		if country != "" {
			filter.Country = &country
		}
	}
	if req.ReleaseYearFrom != nil {
		year := req.GetReleaseYearFrom()
		filter.ReleaseYearFrom = &year
	}
	if req.ReleaseYearTo != nil {
		year := req.GetReleaseYearTo()
		filter.ReleaseYearTo = &year
	}
	if req.ImdbRatingFrom != nil {
		rating := req.GetImdbRatingFrom()
		filter.IMDbRatingFrom = &rating
	}
	if req.ImdbRatingTo != nil {
		rating := req.GetImdbRatingTo()
		filter.IMDbRatingTo = &rating
	}
	if filter.ReleaseYearFrom != nil && filter.ReleaseYearTo != nil && *filter.ReleaseYearFrom > *filter.ReleaseYearTo {
		return ports.MovieFilter{}, status.Error(codes.InvalidArgument, "release_year_from must be less than or equal to release_year_to")
	}
	if filter.IMDbRatingFrom != nil && filter.IMDbRatingTo != nil && *filter.IMDbRatingFrom > *filter.IMDbRatingTo {
		return ports.MovieFilter{}, status.Error(codes.InvalidArgument, "imdb_rating_from must be less than or equal to imdb_rating_to")
	}

	genres, err := protoGenresToDomain(req.GetGenres(), "genres")
	if err != nil {
		return ports.MovieFilter{}, err
	}
	filter.Genres = genres

	actors, err := protoPeopleToDomain(req.GetActors(), "actors")
	if err != nil {
		return ports.MovieFilter{}, err
	}
	filter.Actors = actors

	directors, err := protoPeopleToDomain(req.GetDirectors(), "directors")
	if err != nil {
		return ports.MovieFilter{}, err
	}
	filter.Directors = directors

	return filter, nil
}

func protoGenresToDomain(genres []*movieservicev1.Genre, field string) ([]domain.Genre, error) {
	result := make([]domain.Genre, 0, len(genres))

	for _, genre := range genres {
		if genre == nil {
			continue
		}

		mapped := domain.Genre{Name: strings.TrimSpace(genre.GetName())}
		if genre.GetId() != "" {
			genreID, err := parseUUID(genre.GetId(), field+".id")
			if err != nil {
				return nil, err
			}
			mapped.ID = genreID
		}

		if mapped.ID == uuid.Nil && mapped.Name == "" {
			continue
		}

		result = append(result, mapped)
	}

	return result, nil
}

func protoPeopleToDomain(people []*movieservicev1.Person, field string) ([]domain.Person, error) {
	result := make([]domain.Person, 0, len(people))

	for _, person := range people {
		if person == nil {
			continue
		}

		mapped := domain.Person{
			Name:    strings.TrimSpace(person.GetName()),
			Surname: strings.TrimSpace(person.GetSurname()),
		}
		if person.GetId() != "" {
			personID, err := parseUUID(person.GetId(), field+".id")
			if err != nil {
				return nil, err
			}
			mapped.ID = personID
		}
		if person.BirthYear != nil {
			mapped.BirthYear = person.GetBirthYear()
		}

		if mapped.ID == uuid.Nil && mapped.Name == "" && mapped.Surname == "" && mapped.BirthYear == 0 {
			continue
		}

		result = append(result, mapped)
	}

	return result, nil
}

func genresToProto(genres []domain.Genre) []*movieservicev1.Genre {
	result := make([]*movieservicev1.Genre, 0, len(genres))

	for _, genre := range genres {
		mapped := &movieservicev1.Genre{
			Name: strings.TrimSpace(genre.Name),
		}
		if genre.ID != uuid.Nil {
			mapped.Id = genre.ID.String()
		}
		if mapped.Id == "" && mapped.Name == "" {
			continue
		}

		result = append(result, mapped)
	}

	return result
}

func peopleToProto(people []domain.Person) []*movieservicev1.Person {
	result := make([]*movieservicev1.Person, 0, len(people))

	for _, person := range people {
		mapped := &movieservicev1.Person{
			Name:    strings.TrimSpace(person.Name),
			Surname: strings.TrimSpace(person.Surname),
		}
		if person.ID != uuid.Nil {
			mapped.Id = person.ID.String()
		}
		if person.BirthYear > 0 {
			birthYear := person.BirthYear
			mapped.BirthYear = &birthYear
		}
		if mapped.Id == "" && mapped.Name == "" && mapped.Surname == "" && mapped.BirthYear == nil {
			continue
		}

		result = append(result, mapped)
	}

	return result
}

func protoToMovie(movie *movieservicev1.Movie) (domain.Movie, error) {
	if movie == nil {
		return domain.Movie{}, status.Error(codes.InvalidArgument, "movie is required")
	}

	var mapped domain.Movie

	if movie.GetMovieId() != "" {
		movieID, err := parseUUID(movie.GetMovieId(), "movie.movie_id")
		if err != nil {
			return domain.Movie{}, err
		}
		mapped.MovieID = movieID
	}

	genres, err := protoGenresToDomain(movie.GetGenres(), "movie.genres")
	if err != nil {
		return domain.Movie{}, err
	}
	actors, err := protoPeopleToDomain(movie.GetActors(), "movie.actors")
	if err != nil {
		return domain.Movie{}, err
	}
	directors, err := protoPeopleToDomain(movie.GetDirectors(), "movie.directors")
	if err != nil {
		return domain.Movie{}, err
	}

	mapped.Title = strings.TrimSpace(movie.GetTitle())
	mapped.Description = strings.TrimSpace(movie.GetDescription())
	mapped.Genres = genres
	mapped.Actors = actors
	mapped.Directors = directors
	mapped.Country = strings.TrimSpace(movie.GetCountry())
	mapped.ReleaseYear = movie.GetReleaseYear()
	mapped.IMDbRating = movie.GetImdbRating()

	return mapped, nil
}

func movieToProto(movie domain.Movie) *movieservicev1.Movie {
	return &movieservicev1.Movie{
		MovieId:     movie.MovieID.String(),
		Title:       movie.Title,
		Description: movie.Description,
		Genres:      genresToProto(movie.Genres),
		Actors:      peopleToProto(movie.Actors),
		Directors:   peopleToProto(movie.Directors),
		Country:     movie.Country,
		ReleaseYear: movie.ReleaseYear,
		ImdbRating:  movie.IMDbRating,
	}
}

func parseUUID(rawValue, field string) (uuid.UUID, error) {
	value := strings.TrimSpace(rawValue)
	if value == "" {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "%s is required", field)
	}

	parsed, err := uuid.Parse(value)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "%s must be a valid UUID", field)
	}

	return parsed, nil
}
