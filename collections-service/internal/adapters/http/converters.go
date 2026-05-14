package http

import (
	"movie_collection/api/proto/moviecollectionv1"
	"movie_collection/internal/core/domain"
	"movie_collection/internal/core/ports"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func listRequestToFilter(req *moviecollectionv1.ListMoviesRequest) (ports.MovieFilter, error) {
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

func protoGenresToDomain(genres []*moviecollectionv1.Genre, field string) ([]domain.Genre, error) {
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

func protoPeopleToDomain(people []*moviecollectionv1.Person, field string) ([]domain.Person, error) {
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

func genresToProto(genres []domain.Genre) []*moviecollectionv1.Genre {
	result := make([]*moviecollectionv1.Genre, 0, len(genres))

	for _, genre := range genres {
		mapped := &moviecollectionv1.Genre{
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

func peopleToProto(people []domain.Person) []*moviecollectionv1.Person {
	result := make([]*moviecollectionv1.Person, 0, len(people))

	for _, person := range people {
		mapped := &moviecollectionv1.Person{
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

func protoToMovie(movie *moviecollectionv1.Movie) (domain.Movie, error) {
	var mapped domain.Movie

	if movie == nil {
		return mapped, status.Error(codes.InvalidArgument, "movie is required")
	}

	if movie.GetMovieId() != "" {
		movieID, err := parseUUID(movie.GetMovieId(), "movie.movie_id")
		if err != nil {
			return domain.Movie{}, err
		}
		mapped.MovieID = movieID
	}

	lastSyncAt, err := timestampToTime(movie.GetLastSyncAt(), "movie.last_sync_at")
	if err != nil {
		return domain.Movie{}, err
	}
	archivedAt, err := timestampPtrToTime(movie.GetArchivedAt(), "movie.archived_at")
	if err != nil {
		return domain.Movie{}, err
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

	mapped = domain.Movie{
		MovieID:       mapped.MovieID,
		Title:         strings.TrimSpace(movie.GetTitle()),
		Description:   strings.TrimSpace(movie.GetDescription()),
		Genres:        genres,
		Actors:        actors,
		Directors:     directors,
		Country:       strings.TrimSpace(movie.GetCountry()),
		ReleaseYear:   movie.GetReleaseYear(),
		IMDbRating:    movie.GetImdbRating(),
		Source:        strings.TrimSpace(movie.GetSource()),
		SourceMovieID: strings.TrimSpace(movie.GetSourceMovieId()),
		LastSyncAt:    lastSyncAt,
		ArchivedAt:    archivedAt,
	}

	return mapped, nil
}

func movieToProto(movie domain.Movie) *moviecollectionv1.Movie {
	return &moviecollectionv1.Movie{
		MovieId:       movie.MovieID.String(),
		Title:         movie.Title,
		Description:   movie.Description,
		Genres:        genresToProto(movie.Genres),
		Actors:        peopleToProto(movie.Actors),
		Directors:     peopleToProto(movie.Directors),
		Country:       movie.Country,
		ReleaseYear:   movie.ReleaseYear,
		ImdbRating:    movie.IMDbRating,
		Source:        movie.Source,
		SourceMovieId: movie.SourceMovieID,
		LastSyncAt:    timeToTimestamp(movie.LastSyncAt),
		ArchivedAt:    timePtrToTimestamp(movie.ArchivedAt),
	}
}

func movieToSnapshotProto(movie domain.Movie) *moviecollectionv1.MovieSnapshot {
	return &moviecollectionv1.MovieSnapshot{
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

func timestampToTime(value *timestamppb.Timestamp, field string) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	if err := value.CheckValid(); err != nil {
		return time.Time{}, status.Errorf(codes.InvalidArgument, "%s is invalid: %v", field, err)
	}
	return value.AsTime().UTC(), nil
}

func timestampPtrToTime(value *timestamppb.Timestamp, field string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}

	parsed, err := timestampToTime(value, field)
	if err != nil {
		return nil, err
	}

	return &parsed, nil
}

func timeToTimestamp(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value.UTC())
}

func timePtrToTimestamp(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return timeToTimestamp(*value)
}
