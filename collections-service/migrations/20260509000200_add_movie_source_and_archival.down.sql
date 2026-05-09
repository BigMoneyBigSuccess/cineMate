DROP INDEX IF EXISTS idx_movies_archived_at;

ALTER TABLE movies
    DROP CONSTRAINT IF EXISTS uq_movies_source_source_movie_id;

ALTER TABLE movies
    DROP COLUMN IF EXISTS archived_at,
    DROP COLUMN IF EXISTS source_movie_id,
    DROP COLUMN IF EXISTS source;
