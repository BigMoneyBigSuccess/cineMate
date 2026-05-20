package ports

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/analytics-service/internal/core/domain"

	"github.com/google/uuid"
)

// FeedbackRepository keeps the raw, explicit feedback signals so future profile
// rebuilding and recommendation experiments can reuse the original data.
type FeedbackRepository interface {
	UpsertFeedback(ctx context.Context, feedback domain.MovieFeedback) error
	RemoveFeedback(ctx context.Context, feedbackID uuid.UUID) error
	ListFeedbackByUser(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error)
	GetFeedbackByID(ctx context.Context, feedbackID uuid.UUID) (domain.MovieFeedback, error)
}
