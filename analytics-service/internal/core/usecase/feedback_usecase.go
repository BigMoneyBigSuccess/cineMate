package usecase

import (
	"context"

	"analytics/internal/core/domain"
	"analytics/internal/core/ports"

	"github.com/google/uuid"
)

type FeedbackUseCase struct {
	feedbackRepo ports.FeedbackRepository
}

func NewFeedbackUseCase(feedbackRepo ports.FeedbackRepository) *FeedbackUseCase {
	return &FeedbackUseCase{feedbackRepo: feedbackRepo}
}

// UpsertFeedback creates new feedback or replaces an existing one.
// When FeedbackID is not provided a new one is generated (create path).
// Passing an existing FeedbackID updates that record (update path).
func (uc *FeedbackUseCase) UpsertFeedback(ctx context.Context, feedback domain.MovieFeedback) error {
	if err := feedback.Validate(); err != nil {
		return err
	}
	if feedback.FeedbackID == uuid.Nil {
		feedback.FeedbackID = uuid.New()
	}
	return uc.feedbackRepo.UpsertFeedback(ctx, feedback)
}

func (uc *FeedbackUseCase) RemoveFeedback(ctx context.Context, feedbackID uuid.UUID) error {
	if feedbackID == uuid.Nil {
		return domain.ErrInvalidMovieFeedback
	}
	return uc.feedbackRepo.RemoveFeedback(ctx, feedbackID)
}

func (uc *FeedbackUseCase) GetFeedback(ctx context.Context, feedbackID uuid.UUID) (domain.MovieFeedback, error) {
	if feedbackID == uuid.Nil {
		return domain.MovieFeedback{}, domain.ErrInvalidMovieFeedback
	}
	return uc.feedbackRepo.GetFeedbackByID(ctx, feedbackID)
}

func (uc *FeedbackUseCase) ListUserFeedback(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error) {
	if userID == uuid.Nil {
		return nil, domain.ErrInvalidUserReference
	}
	return uc.feedbackRepo.ListFeedbackByUser(ctx, userID)
}
