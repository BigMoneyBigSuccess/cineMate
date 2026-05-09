CREATE TABLE movies (
    id uuid PRIMARY KEY,
    title text NOT NULL,
    country text NOT NULL,
    release_year integer NOT NULL CHECK (release_year >= 1888),
    imdb_rating numeric(3,1) NOT NULL CHECK (imdb_rating >= 0 AND imdb_rating <= 10),
    last_sync_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE genres (
    id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE persons (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    surname text NOT NULL,
    birth_year integer CHECK (birth_year >= 1800),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, surname, birth_year)
);

CREATE TABLE movie_genres (
    movie_id uuid NOT NULL REFERENCES movies (id) ON DELETE CASCADE,
    genre_id uuid NOT NULL REFERENCES genres (id) ON DELETE RESTRICT,
    PRIMARY KEY (movie_id, genre_id)
);

CREATE TABLE movie_actors (
    movie_id uuid NOT NULL REFERENCES movies (id) ON DELETE CASCADE,
    person_id uuid NOT NULL REFERENCES persons (id) ON DELETE RESTRICT,
    PRIMARY KEY (movie_id, person_id)
);

CREATE TABLE movie_directors (
    movie_id uuid NOT NULL REFERENCES movies (id) ON DELETE CASCADE,
    person_id uuid NOT NULL REFERENCES persons (id) ON DELETE RESTRICT,
    PRIMARY KEY (movie_id, person_id)
);

CREATE TABLE watchlists (
    user_id uuid NOT NULL,
    movie_id uuid NOT NULL REFERENCES movies (id) ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, movie_id)
);

CREATE INDEX idx_movies_title ON movies (title);
CREATE INDEX idx_movies_country ON movies (country);
CREATE INDEX idx_movies_release_year ON movies (release_year);
CREATE INDEX idx_movies_imdb_rating ON movies (imdb_rating);
CREATE INDEX idx_movie_genres_genre_id ON movie_genres (genre_id);
CREATE INDEX idx_movie_actors_person_id ON movie_actors (person_id);
CREATE INDEX idx_movie_directors_person_id ON movie_directors (person_id);
CREATE INDEX idx_watchlists_movie_id ON watchlists (movie_id);

COMMENT ON TABLE watchlists IS 'Stores user watchlists without a cross-service foreign key to the users service.';
