package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BigMoneyBigSuccess/cineMate/movies-service/internal/core/domain"
	"strings"

	"github.com/google/uuid"
)

func (r *MovieRepository) loadMoviesByIDs(ctx context.Context, ids []uuid.UUID) ([]domain.Movie, error) {
	if len(ids) == 0 {
		return []domain.Movie{}, nil
	}

	args := make([]any, 0, len(ids))
	placeholders := make([]string, 0, len(ids))
	order := make(map[uuid.UUID]int, len(ids))

	for index, id := range ids {
		args = append(args, id)
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+1))
		order[id] = index
	}

	query := baseMovieSelectQuery() + fmt.Sprintf(`
WHERE m.id IN (%s)
  AND m.archived_at IS NULL`, strings.Join(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	movies, err := scanMovies(rows)
	if err != nil {
		return nil, err
	}

	ordered := make([]domain.Movie, len(ids))
	found := make([]bool, len(ids))
	for _, movie := range movies {
		position, ok := order[movie.MovieID]
		if !ok {
			continue
		}
		ordered[position] = movie
		found[position] = true
	}

	result := make([]domain.Movie, 0, len(movies))
	for index, ok := range found {
		if ok {
			result = append(result, ordered[index])
		}
	}

	return result, nil
}

func (r *MovieRepository) replaceGenres(ctx context.Context, tx *sql.Tx, movieID uuid.UUID, genres []domain.Genre) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM movie_genres WHERE movie_id = $1`, movieID); err != nil {
		return err
	}

	for _, genre := range genres {
		if genre.ID == uuid.Nil && strings.TrimSpace(genre.Name) == "" {
			continue
		}

		genreID, err := ensureGenre(ctx, tx, genre)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO movie_genres (movie_id, genre_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`,
			movieID,
			genreID,
		); err != nil {
			return err
		}
	}

	return nil
}

func (r *MovieRepository) replacePeople(ctx context.Context, tx *sql.Tx, table string, movieID uuid.UUID, people []domain.Person) error {
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE movie_id = $1`, table), movieID); err != nil {
		return err
	}

	for _, person := range people {
		if person.ID == uuid.Nil && strings.TrimSpace(person.Name) == "" && strings.TrimSpace(person.Surname) == "" && person.BirthYear == 0 {
			continue
		}

		personID, err := ensurePerson(ctx, tx, person)
		if err != nil {
			return err
		}

		if _, err := tx.ExecContext(
			ctx,
			fmt.Sprintf(`INSERT INTO %s (movie_id, person_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, table),
			movieID,
			personID,
		); err != nil {
			return err
		}
	}

	return nil
}

func resolveMovieIDForUpsert(ctx context.Context, tx *sql.Tx, movie domain.Movie) (uuid.UUID, error) {
	if movieID, found, err := findMovieIDBySource(ctx, tx, movie.Source, movie.SourceMovieID); err != nil {
		return uuid.Nil, err
	} else if found {
		return movieID, nil
	}

	if movie.MovieID != uuid.Nil {
		return movie.MovieID, nil
	}

	return uuid.NewRandom()
}

func findMovieIDBySource(ctx context.Context, tx *sql.Tx, source, sourceMovieID string) (uuid.UUID, bool, error) {
	var movieID uuid.UUID
	err := tx.QueryRowContext(
		ctx,
		`SELECT id
		FROM movies
		WHERE source = $1
		  AND source_movie_id = $2
		LIMIT 1`,
		source,
		sourceMovieID,
	).Scan(&movieID)
	if err == nil {
		return movieID, true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, nil
	}

	return uuid.Nil, false, err
}

func ensureGenre(ctx context.Context, tx *sql.Tx, genre domain.Genre) (uuid.UUID, error) {
	if genre.ID != uuid.Nil {
		var existingID uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM genres WHERE id = $1`, genre.ID).Scan(&existingID)
		if err == nil {
			return existingID, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, err
		}
	}

	name := strings.TrimSpace(genre.Name)
	if name == "" {
		return uuid.Nil, domain.ErrInvalidGenre
	}

	var genreID uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM genres WHERE name = $1`, name).Scan(&genreID)
	if err == nil {
		return genreID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, err
	}

	genreID = genre.ID
	if genreID == uuid.Nil {
		genreID, err = uuid.NewRandom()
		if err != nil {
			return uuid.Nil, err
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO genres (id, name)
		VALUES ($1, $2)
		ON CONFLICT (name) DO NOTHING`,
		genreID,
		name,
	); err != nil {
		return uuid.Nil, err
	}

	if err := tx.QueryRowContext(ctx, `SELECT id FROM genres WHERE name = $1`, name).Scan(&genreID); err != nil {
		return uuid.Nil, err
	}

	return genreID, nil
}

func ensurePerson(ctx context.Context, tx *sql.Tx, person domain.Person) (uuid.UUID, error) {
	if person.ID != uuid.Nil {
		var existingID uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT id FROM persons WHERE id = $1`, person.ID).Scan(&existingID)
		if err == nil {
			return existingID, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, err
		}
	}

	name := strings.TrimSpace(person.Name)
	surname := strings.TrimSpace(person.Surname)
	if name == "" || surname == "" {
		return uuid.Nil, domain.ErrInvalidPerson
	}

	var birthYear any
	if person.BirthYear > 0 {
		birthYear = person.BirthYear
	}

	var personID uuid.UUID
	err := tx.QueryRowContext(
		ctx,
		`SELECT id
		FROM persons
		WHERE name = $1
		  AND surname = $2
		  AND ((birth_year = $3) OR (birth_year IS NULL AND $3 IS NULL))
		LIMIT 1`,
		name,
		surname,
		birthYear,
	).Scan(&personID)
	if err == nil {
		return personID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, err
	}

	personID = person.ID
	if personID == uuid.Nil {
		personID, err = uuid.NewRandom()
		if err != nil {
			return uuid.Nil, err
		}
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO persons (id, name, surname, birth_year)
		VALUES ($1, $2, $3, $4)`,
		personID,
		name,
		surname,
		birthYear,
	); err != nil {
		return uuid.Nil, err
	}

	return personID, nil
}

func baseMovieSelectQuery() string {
	return `
SELECT
	m.id,
	m.title,
	m.description,
	m.country,
	m.release_year,
	m.imdb_rating,
	m.source,
	m.source_movie_id,
	m.last_sync_at,
	m.archived_at,
	COALESCE(genres.genres, '[]'::json) AS genres,
	COALESCE(actors.actors, '[]'::json) AS actors,
	COALESCE(directors.directors, '[]'::json) AS directors
FROM movies m
LEFT JOIN LATERAL (
	SELECT json_agg(
		json_build_object(
			'id', items.id,
			'name', items.name
		)
		ORDER BY items.name, items.id
	) AS genres
	FROM (
		SELECT DISTINCT g.id, g.name
		FROM movie_genres mg
		JOIN genres g ON g.id = mg.genre_id
		WHERE mg.movie_id = m.id
	) items
) genres ON TRUE
LEFT JOIN LATERAL (
	SELECT json_agg(
		json_build_object(
			'id', items.id,
			'name', items.name,
			'surname', items.surname,
			'birth_year', items.birth_year
		)
		ORDER BY items.name, items.surname, items.id
	) AS actors
	FROM (
		SELECT DISTINCT p.id, p.name, p.surname, p.birth_year
		FROM movie_actors ma
		JOIN persons p ON p.id = ma.person_id
		WHERE ma.movie_id = m.id
	) items
) actors ON TRUE
LEFT JOIN LATERAL (
	SELECT json_agg(
		json_build_object(
			'id', items.id,
			'name', items.name,
			'surname', items.surname,
			'birth_year', items.birth_year
		)
		ORDER BY items.name, items.surname, items.id
	) AS directors
	FROM (
		SELECT DISTINCT p.id, p.name, p.surname, p.birth_year
		FROM movie_directors md
		JOIN persons p ON p.id = md.person_id
		WHERE md.movie_id = m.id
	) items
) directors ON TRUE`
}

func scanMovies(rows *sql.Rows) ([]domain.Movie, error) {
	var movies []domain.Movie

	for rows.Next() {
		var (
			movie         domain.Movie
			archivedAt    sql.NullTime
			genresJSON    []byte
			actorsJSON    []byte
			directorsJSON []byte
		)

		if err := rows.Scan(
			&movie.MovieID,
			&movie.Title,
			&movie.Description,
			&movie.Country,
			&movie.ReleaseYear,
			&movie.IMDbRating,
			&movie.Source,
			&movie.SourceMovieID,
			&movie.LastSyncAt,
			&archivedAt,
			&genresJSON,
			&actorsJSON,
			&directorsJSON,
		); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(genresJSON, &movie.Genres); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(actorsJSON, &movie.Actors); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(directorsJSON, &movie.Directors); err != nil {
			return nil, err
		}
		if archivedAt.Valid {
			movie.ArchivedAt = &archivedAt.Time
		}

		movies = append(movies, movie)
	}

	return movies, rows.Err()
}

func buildGenreFilterClause(genres []domain.Genre, addArg func(any) string) string {
	var conditions []string
	var ids []string
	var names []string

	for _, genre := range genres {
		if genre.ID != uuid.Nil {
			ids = append(ids, addArg(genre.ID))
		}
		if genre.Name != "" {
			names = append(names, addArg(genre.Name))
		}
	}

	if len(ids) > 0 {
		conditions = append(conditions, fmt.Sprintf("g.id IN (%s)", strings.Join(ids, ", ")))
	}
	if len(names) > 0 {
		conditions = append(conditions, fmt.Sprintf("g.name IN (%s)", strings.Join(names, ", ")))
	}
	if len(conditions) == 0 {
		return ""
	}

	return fmt.Sprintf(`EXISTS (
	SELECT 1
	FROM movie_genres mg
	JOIN genres g ON g.id = mg.genre_id
	WHERE mg.movie_id = m.id
	  AND (%s)
)`, strings.Join(conditions, " OR "))
}

func buildPersonFilterClause(table, alias string, people []domain.Person, addArg func(any) string) string {
	var peopleClauses []string

	for _, person := range people {
		if person.ID != uuid.Nil {
			peopleClauses = append(peopleClauses, fmt.Sprintf("p.id = %s", addArg(person.ID)))
			continue
		}

		var fields []string
		if name := strings.TrimSpace(person.Name); name != "" {
			fields = append(fields, fmt.Sprintf("p.name = %s", addArg(name)))
		}
		if surname := strings.TrimSpace(person.Surname); surname != "" {
			fields = append(fields, fmt.Sprintf("p.surname = %s", addArg(surname)))
		}
		if person.BirthYear > 0 {
			fields = append(fields, fmt.Sprintf("p.birth_year = %s", addArg(person.BirthYear)))
		}
		if len(fields) == 0 {
			continue
		}

		peopleClauses = append(peopleClauses, "("+strings.Join(fields, " AND ")+")")
	}

	if len(peopleClauses) == 0 {
		return ""
	}

	return fmt.Sprintf(`EXISTS (
	SELECT 1
	FROM %s %s
	JOIN persons p ON p.id = %s.person_id
	WHERE %s.movie_id = m.id
	  AND (%s)
)`, table, alias, alias, alias, strings.Join(peopleClauses, " OR "))
}

func buildMovieOrderBy(sortBy, sortOrder string) string {
	allowedColumns := map[string]string{
		"id":           "m.id",
		"movie_id":     "m.id",
		"title":        "m.title",
		"country":      "m.country",
		"release_year": "m.release_year",
		"imdb_rating":  "m.imdb_rating",
		"source":       "m.source",
		"last_sync_at": "m.last_sync_at",
		"archived_at":  "m.archived_at",
	}

	column := allowedColumns[sortBy]
	if column == "" {
		column = "m.title"
	}

	order := "ASC"
	if strings.EqualFold(sortOrder, "desc") {
		order = "DESC"
	}

	return fmt.Sprintf("ORDER BY %s %s, m.id ASC", column, order)
}

func personDisplayNameExpr(alias string) string {
	return fmt.Sprintf("concat_ws(' ', %s.name, %s.surname)", alias, alias)
}
