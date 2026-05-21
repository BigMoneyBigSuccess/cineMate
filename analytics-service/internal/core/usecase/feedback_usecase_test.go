package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"

	"github.com/google/uuid"
)

// Note: mockFeedbackRepo, mockProfileRepo are defined in recommendation_usecase_test.go
// (same package), so they are reused here.

// --- UpsertFeedback ---

func TestFeedbackUseCase_UpsertFeedback_InvalidFeedback_ReturnsValidationError(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{})
	err := uc.UpsertFeedback(context.Background(), domain.MovieFeedback{
		UserID:  uuid.Nil, // invalid
		MovieID: uuid.New(),
		Rating:  5,
	})
	if !errors.Is(err, domain.ErrInvalidMovieFeedback) {
		t.Errorf("expected ErrInvalidMovieFeedback, got %v", err)
	}
}

func TestFeedbackUseCase_UpsertFeedback_GeneratesIDWhenNil(t *testing.T) {
	var savedFeedback domain.MovieFeedback
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		upsertFn: func(_ context.Context, fb domain.MovieFeedback) error {
			savedFeedback = fb
			return nil
		},
	})

	err := uc.UpsertFeedback(context.Background(), domain.MovieFeedback{
		FeedbackID: uuid.Nil,
		UserID:     uuid.New(),
		MovieID:    uuid.New(),
		Rating:     5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if savedFeedback.FeedbackID == uuid.Nil {
		t.Error("expected a new FeedbackID to be generated")
	}
}

func TestFeedbackUseCase_UpsertFeedback_PreservesExistingID(t *testing.T) {
	existingID := uuid.New()
	var savedFeedback domain.MovieFeedback
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		upsertFn: func(_ context.Context, fb domain.MovieFeedback) error {
			savedFeedback = fb
			return nil
		},
	})

	_ = uc.UpsertFeedback(context.Background(), domain.MovieFeedback{
		FeedbackID: existingID,
		UserID:     uuid.New(),
		MovieID:    uuid.New(),
		Rating:     5,
	})
	if savedFeedback.FeedbackID != existingID {
		t.Errorf("expected existing FeedbackID %s to be preserved, got %s", existingID, savedFeedback.FeedbackID)
	}
}

func TestFeedbackUseCase_UpsertFeedback_RepoError_Propagates(t *testing.T) {
	repoErr := errors.New("repo down")
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		upsertFn: func(_ context.Context, _ domain.MovieFeedback) error { return repoErr },
	})
	err := uc.UpsertFeedback(context.Background(), domain.MovieFeedback{
		UserID: uuid.New(), MovieID: uuid.New(), Rating: 5,
	})
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repoErr, got %v", err)
	}
}

// --- RemoveFeedback ---

func TestFeedbackUseCase_RemoveFeedback_NilID_ReturnsError(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{})
	err := uc.RemoveFeedback(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidMovieFeedback) {
		t.Errorf("expected ErrInvalidMovieFeedback, got %v", err)
	}
}

func TestFeedbackUseCase_RemoveFeedback_ValidID_DelegatesToRepo(t *testing.T) {
	removeCalled := false
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		removeFn: func(_ context.Context, _ uuid.UUID) error {
			removeCalled = true
			return nil
		},
	})
	if err := uc.RemoveFeedback(context.Background(), uuid.New()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !removeCalled {
		t.Error("expected repo.RemoveFeedback to be called")
	}
}

// --- GetFeedback ---

func TestFeedbackUseCase_GetFeedback_NilID_ReturnsError(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{})
	_, err := uc.GetFeedback(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidMovieFeedback) {
		t.Errorf("expected ErrInvalidMovieFeedback, got %v", err)
	}
}

func TestFeedbackUseCase_GetFeedback_ValidID_ReturnsFeedback(t *testing.T) {
	expected := domain.MovieFeedback{
		FeedbackID: uuid.New(),
		UserID:     uuid.New(),
		MovieID:    uuid.New(),
		Rating:     8,
	}
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		getByIDFn: func(_ context.Context, _ uuid.UUID) (domain.MovieFeedback, error) {
			return expected, nil
		},
	})
	fb, err := uc.GetFeedback(context.Background(), expected.FeedbackID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fb.FeedbackID != expected.FeedbackID {
		t.Errorf("FeedbackID mismatch: expected %s, got %s", expected.FeedbackID, fb.FeedbackID)
	}
}

// --- ListUserFeedback ---

func TestFeedbackUseCase_ListUserFeedback_NilUserID_ReturnsError(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{})
	_, err := uc.ListUserFeedback(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidUserReference) {
		t.Errorf("expected ErrInvalidUserReference, got %v", err)
	}
}

func TestFeedbackUseCase_ListUserFeedback_ValidUserID_ReturnsSlice(t *testing.T) {
	userID := uuid.New()
	expected := []domain.MovieFeedback{
		{FeedbackID: uuid.New(), UserID: userID, MovieID: uuid.New(), Rating: 6},
		{FeedbackID: uuid.New(), UserID: userID, MovieID: uuid.New(), Rating: 9},
	}
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		listFn: func(_ context.Context, _ uuid.UUID) ([]domain.MovieFeedback, error) {
			return expected, nil
		},
	})
	fbs, err := uc.ListUserFeedback(context.Background(), userID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fbs) != 2 {
		t.Errorf("expected 2 feedbacks, got %d", len(fbs))
	}
}

func TestFeedbackUseCase_ListUserFeedback_EmptyList_ReturnsNilError(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{
		listFn: func(_ context.Context, _ uuid.UUID) ([]domain.MovieFeedback, error) {
			return nil, nil
		},
	})
	fbs, err := uc.ListUserFeedback(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fbs != nil {
		t.Errorf("expected nil slice, got %v", fbs)
	}
}
