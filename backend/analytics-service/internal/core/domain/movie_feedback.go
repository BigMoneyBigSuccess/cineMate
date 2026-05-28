package domain

import "github.com/google/uuid"

type MovieFeedback struct {
	FeedbackID uuid.UUID `json:"feedback_id"`
	UserID     uuid.UUID `json:"user_id"`
	MovieID    uuid.UUID `json:"movie_id"`
	Rating     int32     `json:"rating,omitempty"`
	Title      *string   `json:"title,omitempty"`
	Content    *string   `json:"content,omitempty"`
}

func (f MovieFeedback) Validate() error {
	if f.UserID == uuid.Nil || f.MovieID == uuid.Nil {
		return ErrInvalidMovieFeedback
	}
	if f.Rating < 1 || f.Rating > 10 {
		return ErrInvalidMovieFeedback
	}
	return nil
}
