package domain

import "github.com/google/uuid"

type UserPreferenceProfile struct {
	UserID             uuid.UUID `json:"user_id"`
	PreferredGenres    []Genre   `json:"preferred_genres"`
	PreferredActors    []Person  `json:"preferred_actors"`
	PreferredDirectors []Person  `json:"preferred_directors"`
	AverageRating      float32   `json:"average_rating"`
}

func NewEmptyUserPreferenceProfile(userID uuid.UUID) UserPreferenceProfile {
	return UserPreferenceProfile{
		UserID: userID,
	}
}

func (p UserPreferenceProfile) Validate() error {
	if p.UserID == uuid.Nil {
		return ErrInvalidUserPreferenceProfile
	}
	if p.AverageRating < 0 || p.AverageRating > 10 {
		return ErrInvalidUserPreferenceProfile
	}
	return nil
}
