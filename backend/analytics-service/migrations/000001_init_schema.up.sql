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
    -- NULL when the recommendation comes from the AI strategy and no movie
    -- could be parsed from the model response (see ai_response).
    movie_id           UUID,
    -- raw AI model output; set only for ai_model_based strategy.
    ai_response        TEXT,
    rank               SMALLINT                NOT NULL CHECK (rank >= 1),
    strategy           recommendation_strategy NOT NULL,
    -- defaults to 'dismiss'; updated to 'click' when the user interacts
    interaction        interaction_type        NOT NULL DEFAULT 'dismiss',
    generated_at       TIMESTAMPTZ             NOT NULL,
    CONSTRAINT chk_movie_or_ai CHECK (movie_id IS NOT NULL OR ai_response IS NOT NULL)
);

CREATE INDEX ix_movie_rec_user_id    ON movie_recommendations (user_id);
CREATE INDEX ix_movie_rec_session_id ON movie_recommendations (session_id);
-- supports duplicate-avoidance checks (only rows with a known movie_id)
CREATE INDEX ix_movie_rec_user_movie ON movie_recommendations (user_id, movie_id) WHERE movie_id IS NOT NULL;
-- ordered rank lookup within a session (most common read pattern)
CREATE INDEX ix_movie_rec_session_rank  ON movie_recommendations (session_id, rank);
-- latest-N recommendations per user without a sort step
CREATE INDEX ix_movie_rec_user_recent   ON movie_recommendations (user_id, generated_at DESC);

-- ============================================================
-- auto-stamp updated_at
-- ============================================================
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_movie_feedback_updated_at
BEFORE UPDATE ON movie_feedback
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ============================================================
-- keep average_rating in user_preference_profiles in sync
-- ============================================================
CREATE OR REPLACE FUNCTION sync_average_rating()
RETURNS TRIGGER AS $$
DECLARE
    v_user_id UUID;
    v_avg     REAL;
BEGIN
    v_user_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;

    SELECT COALESCE(AVG(rating::REAL), 0)
    INTO   v_avg
    FROM   movie_feedback
    WHERE  user_id = v_user_id;

    INSERT INTO user_preference_profiles (user_id, average_rating, updated_at)
    VALUES (v_user_id, v_avg, NOW())
    ON CONFLICT (user_id) DO UPDATE
        SET average_rating = EXCLUDED.average_rating,
            updated_at     = EXCLUDED.updated_at;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- covers insert, rating edits, and deletes — all events that shift the average
CREATE TRIGGER trg_sync_average_rating
AFTER INSERT OR UPDATE OF rating OR DELETE ON movie_feedback
FOR EACH ROW EXECUTE FUNCTION sync_average_rating();
