package engine

import (
	"context"
	"sort"
	"strings"

	"analytics/internal/core/domain"
	"analytics/internal/core/ports"

	"github.com/google/uuid"
)

// Score weights — genres are the strongest taste signal; actors and directors are
// secondary. IMDb rating provides a base so highly-rated films rank above noise.
const (
	weightGenre    = 3.0
	weightActor    = 1.5
	weightDirector = 1.5
)

func (e *Engine) candidatesByProfile(ctx context.Context, filter ports.RecommendationFilter) ([]domain.MovieSnapshot, error) {
	p := filter.Profile
	need := candidateBuffer(filter.Limit)

	pool, err := e.fetchProfilePool(ctx, p, need)
	if err != nil {
		return nil, err
	}

	// Fallback: if the profile-matched pool is too thin, pad with top-rated movies.
	if len(pool) < need {
		top, err := e.movies.ListMovies(ctx, ports.MovieFilter{
			Limit:     need - len(pool),
			SortBy:    "imdb_rating",
			SortOrder: "desc",
		})
		if err != nil {
			return nil, err
		}
		pool = appendUnique(pool, top)
	}

	return scoreAndSort(pool, p), nil
}

// fetchProfilePool fetches candidates by genres, then actors, then directors,
// stopping early once the pool is large enough.
func (e *Engine) fetchProfilePool(ctx context.Context, p domain.UserPreferenceProfile, need int) ([]domain.MovieSnapshot, error) {
	var pool []domain.MovieSnapshot

	if len(p.PreferredGenres) > 0 {
		movies, err := e.movies.ListMovies(ctx, ports.MovieFilter{
			Genres:    p.PreferredGenres,
			Limit:     need,
			SortBy:    "imdb_rating",
			SortOrder: "desc",
		})
		if err != nil {
			return nil, err
		}
		pool = appendUnique(pool, movies)
	}

	if len(pool) < need && len(p.PreferredActors) > 0 {
		movies, err := e.movies.ListMovies(ctx, ports.MovieFilter{
			Actors:    p.PreferredActors,
			Limit:     need - len(pool),
			SortBy:    "imdb_rating",
			SortOrder: "desc",
		})
		if err != nil {
			return nil, err
		}
		pool = appendUnique(pool, movies)
	}

	if len(pool) < need && len(p.PreferredDirectors) > 0 {
		movies, err := e.movies.ListMovies(ctx, ports.MovieFilter{
			Directors: p.PreferredDirectors,
			Limit:     need - len(pool),
			SortBy:    "imdb_rating",
			SortOrder: "desc",
		})
		if err != nil {
			return nil, err
		}
		pool = appendUnique(pool, movies)
	}

	return pool, nil
}

// scoreAndSort ranks candidates by how well they match the user's full profile.
func scoreAndSort(candidates []domain.MovieSnapshot, p domain.UserPreferenceProfile) []domain.MovieSnapshot {
	type entry struct {
		movie domain.MovieSnapshot
		score float64
	}

	scored := make([]entry, len(candidates))
	for i, m := range candidates {
		s := float64(m.IMDbRating)
		for _, g := range m.Genres {
			if genreMatches(g, p.PreferredGenres) {
				s += weightGenre
			}
		}
		for _, a := range m.Actors {
			if personMatches(a, p.PreferredActors) {
				s += weightActor
			}
		}
		for _, d := range m.Directors {
			if personMatches(d, p.PreferredDirectors) {
				s += weightDirector
			}
		}
		scored[i] = entry{movie: m, score: s}
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	result := make([]domain.MovieSnapshot, len(scored))
	for i, sc := range scored {
		result[i] = sc.movie
	}
	return result
}

// appendUnique merges src into dst, skipping movies already present by MovieID.
func appendUnique(dst, src []domain.MovieSnapshot) []domain.MovieSnapshot {
	seen := make(map[uuid.UUID]struct{}, len(dst))
	for _, m := range dst {
		seen[m.MovieID] = struct{}{}
	}
	for _, m := range src {
		if _, ok := seen[m.MovieID]; !ok {
			dst = append(dst, m)
			seen[m.MovieID] = struct{}{}
		}
	}
	return dst
}

// candidateBuffer fetches more candidates than the limit to give rankCandidates
// enough headroom after deduplication removes already-seen movies.
func candidateBuffer(limit int) int {
	return limit * 3
}

func genreMatches(g domain.Genre, preferred []domain.Genre) bool {
	for _, pg := range preferred {
		if g.ID != uuid.Nil && g.ID == pg.ID {
			return true
		}
		if strings.EqualFold(g.Name, pg.Name) {
			return true
		}
	}
	return false
}

func personMatches(p domain.Person, preferred []domain.Person) bool {
	for _, pp := range preferred {
		if p.ID != uuid.Nil && p.ID == pp.ID {
			return true
		}
		if strings.EqualFold(p.Name, pp.Name) && strings.EqualFold(p.Surname, pp.Surname) {
			return true
		}
	}
	return false
}
