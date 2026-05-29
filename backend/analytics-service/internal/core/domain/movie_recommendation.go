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

var ValidStrategies = map[RecommendationStrategy]struct{}{
	StrategyPreferenceProfileBased: {},
	StrategyGenresBased:            {},
	StrategyActorsBased:            {},
	StrategyDirectorsBased:         {},
	StrategyAIModelBased:           {},
}

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
	MovieID          *uuid.UUID             `json:"movie_id,omitempty"`
	AIResponse       *string                `json:"ai_response,omitempty"`
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
	if r.MovieID == nil && r.AIResponse == nil {
		return ErrInvalidMovieRecommendation
	}
	if r.MovieID != nil && *r.MovieID == uuid.Nil {
		return ErrInvalidMovieRecommendation
	}
	if r.Rank < 1 {
		return ErrInvalidMovieRecommendation
	}
	if _, ok := ValidStrategies[r.Strategy]; !ok {
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
