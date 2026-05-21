package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestUserPreferenceProfile_Validate_HappyPath(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.New(), AverageRating: 7.5}
	if err := p.Validate(); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestUserPreferenceProfile_Validate_ZeroAverageRatingIsValid(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.New(), AverageRating: 0}
	if err := p.Validate(); err != nil {
		t.Errorf("zero AverageRating should be valid, got %v", err)
	}
}

func TestUserPreferenceProfile_Validate_MaxAverageRatingIsValid(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.New(), AverageRating: 10}
	if err := p.Validate(); err != nil {
		t.Errorf("AverageRating 10 should be valid, got %v", err)
	}
}

func TestUserPreferenceProfile_Validate_NilUserID_ReturnsError(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.Nil, AverageRating: 5}
	if err := p.Validate(); err == nil {
		t.Error("expected error for nil UserID")
	}
}

func TestUserPreferenceProfile_Validate_NegativeAverageRating_ReturnsError(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.New(), AverageRating: -0.1}
	if err := p.Validate(); err == nil {
		t.Error("expected error for negative AverageRating")
	}
}

func TestUserPreferenceProfile_Validate_AverageRatingAboveMax_ReturnsError(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.New(), AverageRating: 10.1}
	if err := p.Validate(); err == nil {
		t.Error("expected error for AverageRating > 10")
	}
}

func TestUserPreferenceProfile_Validate_ReturnsCorrectSentinel(t *testing.T) {
	p := UserPreferenceProfile{UserID: uuid.Nil}
	if err := p.Validate(); err != ErrInvalidUserPreferenceProfile {
		t.Errorf("expected ErrInvalidUserPreferenceProfile, got %v", err)
	}
}

func TestNewEmptyUserPreferenceProfile_SetsUserID(t *testing.T) {
	id := uuid.New()
	p := NewEmptyUserPreferenceProfile(id)
	if p.UserID != id {
		t.Errorf("expected UserID %s, got %s", id, p.UserID)
	}
}

func TestNewEmptyUserPreferenceProfile_HasZeroLists(t *testing.T) {
	p := NewEmptyUserPreferenceProfile(uuid.New())
	if len(p.PreferredGenres) != 0 {
		t.Error("PreferredGenres should be empty")
	}
	if len(p.PreferredActors) != 0 {
		t.Error("PreferredActors should be empty")
	}
	if len(p.PreferredDirectors) != 0 {
		t.Error("PreferredDirectors should be empty")
	}
	if p.AverageRating != 0 {
		t.Errorf("AverageRating should be 0, got %f", p.AverageRating)
	}
}

func TestNewEmptyUserPreferenceProfile_IsValidAfterCreation(t *testing.T) {
	p := NewEmptyUserPreferenceProfile(uuid.New())
	if err := p.Validate(); err != nil {
		t.Errorf("empty profile should be valid, got %v", err)
	}
}
