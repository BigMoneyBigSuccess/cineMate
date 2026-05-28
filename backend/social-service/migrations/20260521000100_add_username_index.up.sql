ALTER TABLE user_profiles ALTER COLUMN username DROP DEFAULT;
ALTER TABLE user_profiles ADD CONSTRAINT user_profiles_username_unique UNIQUE (username);

CREATE INDEX idx_user_profiles_username ON user_profiles (username);
