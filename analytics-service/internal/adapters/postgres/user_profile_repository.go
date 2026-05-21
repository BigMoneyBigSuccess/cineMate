package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserProfileRepository struct {
	db *pgxpool.Pool
}

func NewUserProfileRepository(db *pgxpool.Pool) *UserProfileRepository {
	return &UserProfileRepository{db: db}
}

func (r *UserProfileRepository) UpsertProfile(ctx context.Context, profile domain.UserPreferenceProfile) error {
	genres, err := marshalJSONOrEmpty(profile.PreferredGenres)
	if err != nil {
		return fmt.Errorf("marshal preferred_genres: %w", err)
	}
	actors, err := marshalJSONOrEmpty(profile.PreferredActors)
	if err != nil {
		return fmt.Errorf("marshal preferred_actors: %w", err)
	}
	directors, err := marshalJSONOrEmpty(profile.PreferredDirectors)
	if err != nil {
		return fmt.Errorf("marshal preferred_directors: %w", err)
	}

	const q = `
		INSERT INTO user_preference_profiles
		    (user_id, preferred_genres, preferred_actors, preferred_directors, average_rating, updated_at)
		VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5, NOW())
		ON CONFLICT (user_id) DO UPDATE
			SET preferred_genres    = EXCLUDED.preferred_genres,
			    preferred_actors    = EXCLUDED.preferred_actors,
			    preferred_directors = EXCLUDED.preferred_directors,
			    average_rating      = EXCLUDED.average_rating,
			    updated_at          = NOW()`

	_, err = r.db.Exec(ctx, q,
		profile.UserID,
		genres, actors, directors,
		profile.AverageRating,
	)
	if err != nil {
		return fmt.Errorf("upsert profile: %w", err)
	}
	return nil
}

func (r *UserProfileRepository) RemoveProfile(ctx context.Context, userID uuid.UUID) error {
	const q = `DELETE FROM user_preference_profiles WHERE user_id = $1`
	_, err := r.db.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("remove profile: %w", err)
	}
	return nil
}

func (r *UserProfileRepository) GetOrCreateProfileByUserID(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error) {
	const q = `
		SELECT preferred_genres, preferred_actors, preferred_directors, average_rating
		FROM user_preference_profiles
		WHERE user_id = $1`

	var (
		rawGenres    json.RawMessage
		rawActors    json.RawMessage
		rawDirectors json.RawMessage
		avgRating    float32
	)
	err := r.db.QueryRow(ctx, q, userID).Scan(&rawGenres, &rawActors, &rawDirectors, &avgRating)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NewEmptyUserPreferenceProfile(userID), nil
	}
	if err != nil {
		return domain.UserPreferenceProfile{}, fmt.Errorf("get profile: %w", err)
	}

	profile := domain.UserPreferenceProfile{
		UserID:        userID,
		AverageRating: avgRating,
	}
	if err := json.Unmarshal(rawGenres, &profile.PreferredGenres); err != nil {
		return domain.UserPreferenceProfile{}, fmt.Errorf("unmarshal preferred_genres: %w", err)
	}
	if err := json.Unmarshal(rawActors, &profile.PreferredActors); err != nil {
		return domain.UserPreferenceProfile{}, fmt.Errorf("unmarshal preferred_actors: %w", err)
	}
	if err := json.Unmarshal(rawDirectors, &profile.PreferredDirectors); err != nil {
		return domain.UserPreferenceProfile{}, fmt.Errorf("unmarshal preferred_directors: %w", err)
	}
	return profile, nil
}

var _ ports.UserProfileRepository = (*UserProfileRepository)(nil)
