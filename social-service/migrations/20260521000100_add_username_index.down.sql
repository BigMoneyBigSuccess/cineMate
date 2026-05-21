DROP INDEX IF EXISTS idx_user_profiles_username;
ALTER TABLE user_profiles DROP CONSTRAINT IF EXISTS user_profiles_username_unique;
ALTER TABLE user_profiles ALTER COLUMN username SET DEFAULT '';
