package usecase

import (
	"context"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/logger"

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
	if err := uc.feedbackRepo.UpsertFeedback(ctx, feedback); err != nil {
		return err
	}
	logger.FromContext(ctx).Info("feedback upserted",
		"feedback_id", feedback.FeedbackID,
		"user_id", feedback.UserID,
		"movie_id", feedback.MovieID,
	)
	return nil
}

func (uc *FeedbackUseCase) RemoveFeedback(ctx context.Context, feedbackID uuid.UUID) error {
	if feedbackID == uuid.Nil {
		return domain.ErrInvalidMovieFeedback
	}
	if err := uc.feedbackRepo.RemoveFeedback(ctx, feedbackID); err != nil {
		return err
	}
	logger.FromContext(ctx).Info("feedback removed", "feedback_id", feedbackID)
	return nil
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
