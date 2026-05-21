package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestMovieFeedback_Validate_HappyPath(t *testing.T) {
	fb := MovieFeedback{
		FeedbackID: uuid.New(),
		UserID:     uuid.New(),
		MovieID:    uuid.New(),
		Rating:     7,
	}
	if err := fb.Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestMovieFeedback_Validate_RatingBoundaries(t *testing.T) {
	base := MovieFeedback{UserID: uuid.New(), MovieID: uuid.New()}

	for _, rating := range []int32{1, 10} {
		base.Rating = rating
		if err := base.Validate(); err != nil {
			t.Errorf("rating %d should be valid, got %v", rating, err)
		}
	}
}

func TestMovieFeedback_Validate_NilUserID_ReturnsError(t *testing.T) {
	fb := MovieFeedback{UserID: uuid.Nil, MovieID: uuid.New(), Rating: 5}
	if err := fb.Validate(); err == nil {
		t.Error("expected error for nil UserID")
	}
}

func TestMovieFeedback_Validate_NilMovieID_ReturnsError(t *testing.T) {
	fb := MovieFeedback{UserID: uuid.New(), MovieID: uuid.Nil, Rating: 5}
	if err := fb.Validate(); err == nil {
		t.Error("expected error for nil MovieID")
	}
}

func TestMovieFeedback_Validate_RatingBelowMin_ReturnsError(t *testing.T) {
	fb := MovieFeedback{UserID: uuid.New(), MovieID: uuid.New(), Rating: 0}
	if err := fb.Validate(); err == nil {
		t.Error("expected error for rating 0")
	}
}

func TestMovieFeedback_Validate_RatingAboveMax_ReturnsError(t *testing.T) {
	fb := MovieFeedback{UserID: uuid.New(), MovieID: uuid.New(), Rating: 11}
	if err := fb.Validate(); err == nil {
		t.Error("expected error for rating 11")
	}
}

func TestMovieFeedback_Validate_NegativeRating_ReturnsError(t *testing.T) {
	fb := MovieFeedback{UserID: uuid.New(), MovieID: uuid.New(), Rating: -1}
	if err := fb.Validate(); err == nil {
		t.Error("expected error for negative rating")
	}
}

func TestMovieFeedback_Validate_FeedbackIDNilIsAllowed(t *testing.T) {
	// FeedbackID is assigned by the use case, not required for validation.
	fb := MovieFeedback{FeedbackID: uuid.Nil, UserID: uuid.New(), MovieID: uuid.New(), Rating: 5}
	if err := fb.Validate(); err != nil {
		t.Errorf("nil FeedbackID should be valid at domain level, got %v", err)
	}
}

func TestMovieFeedback_Validate_ReturnsCorrectSentinel(t *testing.T) {
	fb := MovieFeedback{UserID: uuid.Nil, MovieID: uuid.New(), Rating: 5}
	if err := fb.Validate(); err != ErrInvalidMovieFeedback {
		t.Errorf("expected ErrInvalidMovieFeedback, got %v", err)
	}
}
