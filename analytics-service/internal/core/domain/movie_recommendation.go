package domain

import (
	"time"

	"github.com/google/uuid"
)

type RecommendationStrategy string

const (
	StrategyPreferenceProfileBased RecommendationStrategy = "preference_profile_based"
	StrategyGenresBased            RecommendationStrategy = "genres_based"
	StrategyActorsBased            RecommendationStrategy = "actors_based"
	StrategyDirectorsBased         RecommendationStrategy = "directors_based"
	StrategyAIModelBased           RecommendationStrategy = "ai_model_based"
)

type InteractionType string

const (
	InteractionTypeClick   InteractionType = "click"
	InteractionTypeDismiss InteractionType = "dismiss"
)

// MovieRecommendation is an immutable record of what was suggested to a user.
//
// Rank is the 1-based position in the ordered batch (1 = top pick).
//
// Strategy indicates the main logic behind why this movie was recommended.
//
// Interaction should be InteractionTypeDismiss by default,
// and updated to InteractionTypeClick if the user clicks on the recommendation.
type MovieRecommendation struct {
	RecommendationID uuid.UUID              `json:"recommendation_id"`
	SessionID        uuid.UUID              `json:"session_id"`
	UserID           uuid.UUID              `json:"user_id"`
	MovieID          uuid.UUID              `json:"movie_id"`
	Rank             int                    `json:"rank"`
	Strategy         RecommendationStrategy `json:"strategy"`
	GeneratedAt      time.Time              `json:"generated_at"`
	Interaction      InteractionType        `json:"interaction,omitempty"`
}

func (r MovieRecommendation) Validate() error {
	if r.RecommendationID == uuid.Nil {
		return ErrInvalidMovieRecommendation
	}
	if r.SessionID == uuid.Nil {
		return ErrInvalidMovieRecommendation
	}
	if r.UserID == uuid.Nil {
		return ErrInvalidMovieRecommendation
	}
	if r.MovieID == uuid.Nil {
		return ErrInvalidMovieRecommendation
	}
	if r.Rank < 1 {
		return ErrInvalidMovieRecommendation
	}
	var validStrategies = map[RecommendationStrategy]bool{
		StrategyPreferenceProfileBased: true,
		StrategyGenresBased:            true,
		StrategyActorsBased:            true,
		StrategyDirectorsBased:         true,
		StrategyAIModelBased:           true,
	}
	if !validStrategies[r.Strategy] {
		return ErrInvalidMovieRecommendation
	}
	if r.GeneratedAt.IsZero() {
		return ErrInvalidMovieRecommendation
	}
	var validInteractions = map[InteractionType]bool{
		InteractionTypeClick:   true,
		InteractionTypeDismiss: true,
	}
	if !validInteractions[r.Interaction] {
		return ErrInvalidMovieRecommendation
	}
	return nil
}
