DROP TRIGGER IF EXISTS trg_sync_average_rating    ON movie_feedback;
DROP TRIGGER IF EXISTS trg_movie_feedback_updated_at ON movie_feedback;
DROP FUNCTION IF EXISTS sync_average_rating();
DROP FUNCTION IF EXISTS set_updated_at();
DROP TABLE IF EXISTS movie_recommendations;
DROP TABLE IF EXISTS user_preference_profiles;
DROP TABLE IF EXISTS movie_feedback;
DROP TYPE IF EXISTS interaction_type;
DROP TYPE IF EXISTS recommendation_strategy;
