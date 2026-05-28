package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
)

type mockFeedbackRepo struct {
	upsert     func(context.Context, domain.MovieFeedback) error
	remove     func(context.Context, uuid.UUID) error
	listByUser func(context.Context, uuid.UUID) ([]domain.MovieFeedback, error)
	getByID    func(context.Context, uuid.UUID) (domain.MovieFeedback, error)

	lastUpserted domain.MovieFeedback
	lastRemoved  uuid.UUID
}

var _ ports.FeedbackRepository = (*mockFeedbackRepo)(nil)

func (m *mockFeedbackRepo) UpsertFeedback(ctx context.Context, fb domain.MovieFeedback) error {
	m.lastUpserted = fb
	if m.upsert != nil {
		return m.upsert(ctx, fb)
	}
	return nil
}
func (m *mockFeedbackRepo) RemoveFeedback(ctx context.Context, id uuid.UUID) error {
	m.lastRemoved = id
	if m.remove != nil {
		return m.remove(ctx, id)
	}
	return nil
}
func (m *mockFeedbackRepo) ListFeedbackByUser(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error) {
	if m.listByUser != nil {
		return m.listByUser(ctx, userID)
	}
	return nil, nil
}
func (m *mockFeedbackRepo) GetFeedbackByID(ctx context.Context, id uuid.UUID) (domain.MovieFeedback, error) {
	if m.getByID != nil {
		return m.getByID(ctx, id)
	}
	return domain.MovieFeedback{}, nil
}

func validFeedback() domain.MovieFeedback {
	return domain.MovieFeedback{
		UserID:  uuid.New(),
		MovieID: uuid.New(),
		Rating:  7,
	}
}

func TestUpsertFeedback_HappyPath(t *testing.T) {
	repo := &mockFeedbackRepo{}
	uc := NewFeedbackUseCase(repo)

	fb := validFeedback()
	fb.FeedbackID = uuid.New() // explicit ID → update path

	if err := uc.UpsertFeedback(context.Background(), fb); err != nil {
		t.Fatalf("UpsertFeedback returned error: %v", err)
	}
	if repo.lastUpserted.FeedbackID != fb.FeedbackID {
		t.Fatalf("repo received FeedbackID %v, want %v", repo.lastUpserted.FeedbackID, fb.FeedbackID)
	}
}

func TestUpsertFeedback_GeneratesIDWhenNil(t *testing.T) {
	repo := &mockFeedbackRepo{}
	uc := NewFeedbackUseCase(repo)

	fb := validFeedback() // FeedbackID = uuid.Nil

	if err := uc.UpsertFeedback(context.Background(), fb); err != nil {
		t.Fatalf("UpsertFeedback returned error: %v", err)
	}
	if repo.lastUpserted.FeedbackID == uuid.Nil {
		t.Fatal("expected UpsertFeedback to generate a non-nil FeedbackID, got uuid.Nil")
	}
}

func TestUpsertFeedback_ValidationError(t *testing.T) {
	repo := &mockFeedbackRepo{
		upsert: func(context.Context, domain.MovieFeedback) error {
			t.Fatal("repo.UpsertFeedback should not be called when validation fails")
			return nil
		},
	}
	uc := NewFeedbackUseCase(repo)

	bad := domain.MovieFeedback{UserID: uuid.Nil, MovieID: uuid.New(), Rating: 5} // missing UserID

	err := uc.UpsertFeedback(context.Background(), bad)
	if !errors.Is(err, domain.ErrInvalidMovieFeedback) {
		t.Fatalf("err = %v, want ErrInvalidMovieFeedback", err)
	}
}

func TestUpsertFeedback_RepoErrorPropagates(t *testing.T) {
	repoErr := errors.New("db down")
	repo := &mockFeedbackRepo{
		upsert: func(context.Context, domain.MovieFeedback) error { return repoErr },
	}
	uc := NewFeedbackUseCase(repo)

	err := uc.UpsertFeedback(context.Background(), validFeedback())
	if !errors.Is(err, repoErr) {
		t.Fatalf("err = %v, want %v", err, repoErr)
	}
}

func TestRemoveFeedback_HappyPath(t *testing.T) {
	repo := &mockFeedbackRepo{}
	uc := NewFeedbackUseCase(repo)

	id := uuid.New()
	if err := uc.RemoveFeedback(context.Background(), id); err != nil {
		t.Fatalf("RemoveFeedback returned error: %v", err)
	}
	if repo.lastRemoved != id {
		t.Fatalf("repo got id %v, want %v", repo.lastRemoved, id)
	}
}

func TestRemoveFeedback_NilIDRejected(t *testing.T) {
	repo := &mockFeedbackRepo{
		remove: func(context.Context, uuid.UUID) error {
			t.Fatal("repo.RemoveFeedback should not be called with nil ID")
			return nil
		},
	}
	uc := NewFeedbackUseCase(repo)

	err := uc.RemoveFeedback(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidMovieFeedback) {
		t.Fatalf("err = %v, want ErrInvalidMovieFeedback", err)
	}
}

func TestGetFeedback_NilIDRejected(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{})

	_, err := uc.GetFeedback(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidMovieFeedback) {
		t.Fatalf("err = %v, want ErrInvalidMovieFeedback", err)
	}
}

func TestListUserFeedback_NilUserRejected(t *testing.T) {
	uc := NewFeedbackUseCase(&mockFeedbackRepo{})

	_, err := uc.ListUserFeedback(context.Background(), uuid.Nil)
	if !errors.Is(err, domain.ErrInvalidUserReference) {
		t.Fatalf("err = %v, want ErrInvalidUserReference", err)
	}
}
