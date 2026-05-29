CREATE TABLE IF NOT EXISTS user_profiles (
    user_id    uuid        PRIMARY KEY,
    username   TEXT        NOT NULL DEFAULT '',
    bio        TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS follows (
    follower_id uuid        NOT NULL,
    followed_id uuid        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (follower_id, followed_id)
);

CREATE INDEX IF NOT EXISTS idx_follows_followed_id ON follows (followed_id);

