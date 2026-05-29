package syncer

import (
	"fmt"
	"strings"
	"time"

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
)

const maxActors = 15

func mapFilmToMovie(item FilmItem, detail *FilmDetail, staff []StaffMember) domain.Movie {
	movie := domain.Movie{
		Source:        Source,
		SourceMovieID: fmt.Sprintf("%d", item.KinopoiskID),
		LastSyncAt:    time.Now().UTC(),
	}

	if item.NameRu != "" {
		movie.Title = item.NameRu
	} else {
		movie.Title = *item.NameOriginal
	}

	if len(item.Countries) > 0 {
		movie.Country = item.Countries[0].Country
	}

	if item.Year != nil {
		movie.ReleaseYear = int32(*item.Year)
	}

	if item.RatingImdb != nil {
		movie.IMDbRating = *item.RatingImdb
	}

	for _, g := range item.Genres {
		if name := strings.TrimSpace(g.Genre); name != "" {
			movie.Genres = append(movie.Genres, domain.Genre{Name: name})
		}
	}

	if detail != nil && detail.Description != nil {
		movie.Description = *detail.Description
	}

	actorCount := 0
	for _, member := range staff {
		person, ok := parsePerson(member)
		if !ok {
			continue
		}
		switch member.ProfessionKey {
		case "DIRECTOR":
			movie.Directors = append(movie.Directors, person)
		case "ACTOR":
			if actorCount < maxActors {
				movie.Actors = append(movie.Actors, person)
				actorCount++
			}
		}
	}

	return movie
}

// parsePerson splits a staff member's full name into Name and Surname.
// Returns false if the name is empty (member will be skipped).
func parsePerson(member StaffMember) (domain.Person, bool) {
	fullName := strings.TrimSpace(member.NameEn)
	if fullName == "" {
		fullName = strings.TrimSpace(member.NameRu)
	}
	if fullName == "" {
		return domain.Person{}, false
	}

	parts := strings.SplitN(fullName, " ", 2)
	if len(parts) == 2 {
		return domain.Person{
			Name:    strings.TrimSpace(parts[0]),
			Surname: strings.TrimSpace(parts[1]),
		}, true
	}

	// Single-token name: use it for both fields so validation passes.
	return domain.Person{
		Name:    fullName,
		Surname: fullName,
	}, true
}
