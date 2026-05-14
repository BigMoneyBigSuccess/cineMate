-- ============================================================
-- movie_feedback
-- ============================================================
CREATE TABLE movie_feedback (
    feedback_id UUID        PRIMARY KEY,
    user_id     UUID        NOT NULL,
    -- movie_id references movie-collection service; no local FK
    movie_id    UUID        NOT NULL,
    rating      SMALLINT    NOT NULL CHECK (rating BETWEEN 1 AND 10),
    title       TEXT,
    content     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- one record per user per movie (upsert target)
CREATE UNIQUE INDEX ux_movie_feedback_user_movie ON movie_feedback (user_id, movie_id);
CREATE INDEX        ix_movie_feedback_user_id    ON movie_feedback (user_id);

-- ============================================================
-- user_preference_profiles
-- ============================================================
CREATE TABLE user_preference_profiles (
    user_id             UUID  PRIMARY KEY,
    -- denormalized value objects from movie-collection stored as JSONB so the
    -- engine strategies can query them without cross-service joins.
    -- Genre element:  {"id":"<uuid>","name":"<string>"}
    -- Person element: {"id":"<uuid>","name":"<string>","surname":"<string>","birth_year":<int|null>}
    preferred_genres    JSONB       NOT NULL DEFAULT '[]',
    preferred_actors    JSONB       NOT NULL DEFAULT '[]',
    preferred_directors JSONB       NOT NULL DEFAULT '[]',
    average_rating      REAL        NOT NULL DEFAULT 0 CHECK (average_rating BETWEEN 0 AND 10),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- GIN indexes enable containment checks (@>) used by the engine strategies
CREATE INDEX ix_user_pref_genres    ON user_preference_profiles USING GIN (preferred_genres);
CREATE INDEX ix_user_pref_actors    ON user_preference_profiles USING GIN (preferred_actors);
CREATE INDEX ix_user_pref_directors ON user_preference_profiles USING GIN (preferred_directors);

-- ============================================================
-- movie_recommendations
-- ============================================================
CREATE TYPE recommendation_strategy AS ENUM (
    'preference_profile_based',
    'genres_based',
    'actors_based',
    'directors_based',
    'ai_model_based'
);

CREATE TYPE interaction_type AS ENUM (
    'click',
    'dismiss'
);

CREATE TABLE movie_recommendations (
    recommendation_id  UUID                    PRIMARY KEY,
    session_id         UUID                    NOT NULL,
    user_id            UUID                    NOT NULL,
    -- movie_id references movie-collection service; no local FK.
    -- Movie data is fetched from the movie-collection service at read time.
    movie_id           UUID                    NOT NULL,
    rank               SMALLINT                NOT NULL CHECK (rank >= 1),
    strategy           recommendation_strategy NOT NULL,
    -- defaults to 'dismiss'; updated to 'click' when the user interacts
    interaction        interaction_type        NOT NULL DEFAULT 'dismiss',
    generated_at       TIMESTAMPTZ             NOT NULL
);

CREATE INDEX ix_movie_rec_user_id    ON movie_recommendations (user_id);
CREATE INDEX ix_movie_rec_session_id ON movie_recommendations (session_id);
-- supports duplicate-avoidance checks
CREATE INDEX ix_movie_rec_user_movie ON movie_recommendations (user_id, movie_id);
