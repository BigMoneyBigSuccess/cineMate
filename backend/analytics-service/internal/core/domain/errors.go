package domain

import "errors"

var (
	ErrInvalidUserReference             = errors.New("invalid user reference")
	ErrInvalidMovieReference            = errors.New("invalid movie reference")
	ErrInvalidMovieSnapshot             = errors.New("invalid movie snapshot")
	ErrInvalidUserPreferenceProfile     = errors.New("invalid user preference profile")
	ErrInvalidMovieFeedback             = errors.New("invalid movie feedback")
	ErrInvalidMovieRecommendation       = errors.New("invalid movie recommendation")
	ErrInvalidRecommendationRequest     = errors.New("invalid recommendation request")
	ErrInvalidRecommendationInteraction = errors.New("invalid recommendation interaction")
	ErrInvalidGenre                     = errors.New("invalid genre")
	ErrInvalidPerson                    = errors.New("invalid person")
	ErrFeedbackNotFound                 = errors.New("feedback not found")
)
