package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

<<<<<<< HEAD
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"
=======
	"movie_service/internal/core/domain"
	"movie_service/internal/core/ports"
>>>>>>> 26ab2e2 (took out environment variables into .env file & added syncer for fetching films from open api service & took out proto files from movie-service, now they will lie in shared directory)

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ ports.MovieRepository = (*MovieRepository)(nil)

type MovieRepository struct {
	db *pgxpool.Pool
}

func NewMovieRepository(db *pgxpool.Pool) *MovieRepository {
	return &MovieRepository{db: db}
}

func (r *MovieRepository) UpsertMovie(ctx context.Context, movie domain.Movie) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	movieID, err := resolveMovieIDForUpsert(ctx, tx, movie)
	if err != nil {
		return err
	}
	movie.MovieID = movieID

	if movie.LastSyncAt.IsZero() {
		movie.LastSyncAt = time.Now().UTC()
	}

	const q = `
		INSERT INTO movies (
			id,
			title,
			description,
			country,
			release_year,
			imdb_rating,
			source,
			source_movie_id,
			last_sync_at,
			archived_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			country = EXCLUDED.country,
			release_year = EXCLUDED.release_year,
			imdb_rating = EXCLUDED.imdb_rating,
			source = EXCLUDED.source,
			source_movie_id = EXCLUDED.source_movie_id,
			last_sync_at = EXCLUDED.last_sync_at,
			archived_at = NULL`

	if _, err = tx.Exec(ctx, q,
		movie.MovieID,
		movie.Title,
		movie.Description,
		movie.Country,
		movie.ReleaseYear,
		movie.IMDbRating,
		movie.Source,
		movie.SourceMovieID,
		movie.LastSyncAt,
	); err != nil {
		return fmt.Errorf("upsert movie: %w", err)
	}

	if err := r.replaceGenres(ctx, tx, movie.MovieID, movie.Genres); err != nil {
		return err
	}
	if err := r.replacePeople(ctx, tx, "movie_actors", movie.MovieID, movie.Actors); err != nil {
		return err
	}
	if err := r.replacePeople(ctx, tx, "movie_directors", movie.MovieID, movie.Directors); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *MovieRepository) ArchiveMovie(ctx context.Context, id uuid.UUID) error {
	const q = `
		UPDATE movies
		SET archived_at = COALESCE(archived_at, now())
		WHERE id = $1`

	if _, err := r.db.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("archive movie: %w", err)
	}
	return nil
}

func (r *MovieRepository) RemoveMovie(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM movies WHERE id = $1`

	tag, err := r.db.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("remove movie: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (r *MovieRepository) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.Movie, error) {
	query := baseMovieSelectQuery() + `
WHERE m.id = $1
  AND m.archived_at IS NULL`

	rows, err := r.db.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("get movie by id: %w", err)
	}
	defer rows.Close()

	movies, err := scanMovies(rows)
	if err != nil {
		return nil, err
	}
	if len(movies) == 0 {
		return nil, pgx.ErrNoRows
	}

	return &movies[0], nil
}

func (r *MovieRepository) ListMovies(ctx context.Context, filter ports.MovieFilter) ([]domain.Movie, error) {
	var (
		args    []any
		clauses []string
	)

	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	if !filter.IncludeArchived {
		clauses = append(clauses, "m.archived_at IS NULL")
	}

	if filter.Query != "" {
		titlePlaceholder := addArg("%" + filter.Query + "%")
		actorsPlaceholder := addArg("%" + filter.Query + "%")
		directorsPlaceholder := addArg("%" + filter.Query + "%")

		clauses = append(clauses, fmt.Sprintf(`(
	m.title ILIKE %s
	OR EXISTS (
		SELECT 1
		FROM movie_actors ma
		JOIN persons p ON p.id = ma.person_id
		WHERE ma.movie_id = m.id
		  AND %s ILIKE %s
	)
	OR EXISTS (
		SELECT 1
		FROM movie_directors md
		JOIN persons p ON p.id = md.person_id
		WHERE md.movie_id = m.id
		  AND %s ILIKE %s
	)
)`, titlePlaceholder, personDisplayNameExpr("p"), actorsPlaceholder, personDisplayNameExpr("p"), directorsPlaceholder))
	}

	if clause := buildGenreFilterClause(filter.Genres, addArg); clause != "" {
		clauses = append(clauses, clause)
	}
	if clause := buildPersonFilterClause("movie_actors", "ma", filter.Actors, addArg); clause != "" {
		clauses = append(clauses, clause)
	}
	if clause := buildPersonFilterClause("movie_directors", "md", filter.Directors, addArg); clause != "" {
		clauses = append(clauses, clause)
	}
	if filter.Country != nil {
		clauses = append(clauses, fmt.Sprintf("m.country = %s", addArg(*filter.Country)))
	}
	if filter.ReleaseYearFrom != nil {
		clauses = append(clauses, fmt.Sprintf("m.release_year >= %s", addArg(*filter.ReleaseYearFrom)))
	}
	if filter.ReleaseYearTo != nil {
		clauses = append(clauses, fmt.Sprintf("m.release_year <= %s", addArg(*filter.ReleaseYearTo)))
	}
	if filter.IMDbRatingFrom != nil {
		clauses = append(clauses, fmt.Sprintf("m.imdb_rating >= %s", addArg(*filter.IMDbRatingFrom)))
	}
	if filter.IMDbRatingTo != nil {
		clauses = append(clauses, fmt.Sprintf("m.imdb_rating <= %s", addArg(*filter.IMDbRatingTo)))
	}

	query := baseMovieSelectQuery()
	if len(clauses) > 0 {
		query += "\nWHERE " + strings.Join(clauses, "\n  AND ")
	}

	query += "\n" + buildMovieOrderBy(filter.SortBy, filter.SortOrder)

	var pagination []string
	if filter.Limit > 0 {
		pagination = append(pagination, fmt.Sprintf("LIMIT %s", addArg(filter.Limit)))
	}
	if filter.Offset > 0 {
		pagination = append(pagination, fmt.Sprintf("OFFSET %s", addArg(filter.Offset)))
	}
	if len(pagination) > 0 {
		query += "\n" + strings.Join(pagination, " ")
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list movies: %w", err)
	}
	defer rows.Close()

	return scanMovies(rows)
}

var _ ports.MovieRepository = (*MovieRepository)(nil)

// pgx sentinel re-exported so callers don't need to import pgx directly.
var ErrNoRows = pgx.ErrNoRows

func resolveMovieIDForUpsert(ctx context.Context, tx pgx.Tx, movie domain.Movie) (uuid.UUID, error) {
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

func findMovieIDBySource(ctx context.Context, tx pgx.Tx, source, sourceMovieID string) (uuid.UUID, bool, error) {
	const q = `
		SELECT id
		FROM movies
		WHERE source = $1
		  AND source_movie_id = $2
		LIMIT 1`

	var movieID uuid.UUID
	err := tx.QueryRow(ctx, q, source, sourceMovieID).Scan(&movieID)
	if err == nil {
		return movieID, true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return uuid.Nil, false, fmt.Errorf("find movie by source: %w", err)
}
