ALTER TABLE movies
    ADD COLUMN source text,
    ADD COLUMN source_movie_id text,
    ADD COLUMN archived_at timestamptz;

UPDATE movies
SET source = 'legacy',
    source_movie_id = id::text
WHERE source IS NULL
   OR source_movie_id IS NULL;

ALTER TABLE movies
    ALTER COLUMN source SET NOT NULL,
    ALTER COLUMN source_movie_id SET NOT NULL;

ALTER TABLE movies
    ADD CONSTRAINT uq_movies_source_source_movie_id UNIQUE (source, source_movie_id);

CREATE INDEX idx_movies_archived_at ON movies (archived_at);
