package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func validRecommendation() MovieRecommendation {
	movieID := uuid.New()
	return MovieRecommendation{
		RecommendationID: uuid.New(),
		SessionID:        uuid.New(),
		UserID:           uuid.New(),
		MovieID:          &movieID,
		Rank:             1,
		Strategy:         StrategyGenresBased,
		GeneratedAt:      time.Now(),
		Interaction:      InteractionTypeDismiss,
	}
}

func TestMovieRecommendation_Validate_HappyPath(t *testing.T) {
	if err := validRecommendation().Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestMovieRecommendation_Validate_AllStrategiesAreValid(t *testing.T) {
	strategies := []RecommendationStrategy{
		StrategyPreferenceProfileBased,
		StrategyGenresBased,
		StrategyActorsBased,
		StrategyDirectorsBased,
		StrategyAIModelBased,
	}
	for _, s := range strategies {
		r := validRecommendation()
		r.Strategy = s
		if err := r.Validate(); err != nil {
			t.Errorf("strategy %q should be valid, got %v", s, err)
		}
	}
}

func TestMovieRecommendation_Validate_AllInteractionsAreValid(t *testing.T) {
	for _, interaction := range []InteractionType{InteractionTypeClick, InteractionTypeDismiss} {
		r := validRecommendation()
		r.Interaction = interaction
		if err := r.Validate(); err != nil {
			t.Errorf("interaction %q should be valid, got %v", interaction, err)
		}
	}
}

func TestMovieRecommendation_Validate_NilRecommendationID_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.RecommendationID = uuid.Nil
	if err := r.Validate(); err == nil {
		t.Error("expected error for nil RecommendationID")
	}
}

func TestMovieRecommendation_Validate_NilSessionID_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.SessionID = uuid.Nil
	if err := r.Validate(); err == nil {
		t.Error("expected error for nil SessionID")
	}
}

func TestMovieRecommendation_Validate_NilUserID_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.UserID = uuid.Nil
	if err := r.Validate(); err == nil {
		t.Error("expected error for nil UserID")
	}
}

func TestMovieRecommendation_Validate_NilMovieID_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.MovieID = nil
	if err := r.Validate(); err == nil {
		t.Error("expected error when both MovieID and AIResponse are nil")
	}
}

func TestMovieRecommendation_Validate_ZeroMovieID_ReturnsError(t *testing.T) {
	r := validRecommendation()
	zeroID := uuid.Nil
	r.MovieID = &zeroID
	if err := r.Validate(); err == nil {
		t.Error("expected error for zero-value MovieID")
	}
}

func TestMovieRecommendation_Validate_ZeroRank_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.Rank = 0
	if err := r.Validate(); err == nil {
		t.Error("expected error for rank 0")
	}
}

func TestMovieRecommendation_Validate_NegativeRank_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.Rank = -1
	if err := r.Validate(); err == nil {
		t.Error("expected error for negative rank")
	}
}

func TestMovieRecommendation_Validate_UnknownStrategy_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.Strategy = RecommendationStrategy("never_heard_of_it")
	if err := r.Validate(); err == nil {
		t.Error("expected error for unknown strategy")
	}
}

func TestMovieRecommendation_Validate_ZeroGeneratedAt_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.GeneratedAt = time.Time{}
	if err := r.Validate(); err == nil {
		t.Error("expected error for zero GeneratedAt")
	}
}

func TestMovieRecommendation_Validate_UnknownInteraction_ReturnsError(t *testing.T) {
	r := validRecommendation()
	r.Interaction = InteractionType("watch")
	if err := r.Validate(); err == nil {
		t.Error("expected error for unknown interaction")
	}
}

func TestMovieRecommendation_Validate_ReturnsCorrectSentinel(t *testing.T) {
	r := validRecommendation()
	r.UserID = uuid.Nil
	if err := r.Validate(); err != ErrInvalidMovieRecommendation {
		t.Errorf("expected ErrInvalidMovieRecommendation, got %v", err)
	}
}
