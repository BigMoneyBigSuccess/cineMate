package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/google/uuid"
)

type mockProfileRepo struct {
	getProfile     func(context.Context, uuid.UUID) (*domain.UserProfile, error)
	upsertProfile  func(context.Context, domain.UserProfile) error
	searchProfiles func(context.Context, string, int32, int32) ([]domain.UserProfile, int32, error)
}

func (m *mockProfileRepo) GetProfile(ctx context.Context, id uuid.UUID) (*domain.UserProfile, error) {
	if m.getProfile != nil {
		return m.getProfile(ctx, id)
	}
	return nil, nil
}
func (m *mockProfileRepo) UpsertProfile(ctx context.Context, p domain.UserProfile) error {
	if m.upsertProfile != nil {
		return m.upsertProfile(ctx, p)
	}
	return nil
}
func (m *mockProfileRepo) SearchProfiles(ctx context.Context, q string, l, o int32) ([]domain.UserProfile, int32, error) {
	if m.searchProfiles != nil {
		return m.searchProfiles(ctx, q, l, o)
	}
	return nil, 0, nil
}

type mockFollowRepo struct {
	follow       func(context.Context, uuid.UUID, uuid.UUID) error
	unfollow     func(context.Context, uuid.UUID, uuid.UUID) error
	getFollowers func(context.Context, uuid.UUID, int32, int32) ([]uuid.UUID, int32, error)
	isFollowing  func(context.Context, uuid.UUID, uuid.UUID) (bool, error)
}

func (m *mockFollowRepo) Follow(ctx context.Context, a, b uuid.UUID) error {
	if m.follow != nil {
		return m.follow(ctx, a, b)
	}
	return nil
}
func (m *mockFollowRepo) Unfollow(ctx context.Context, a, b uuid.UUID) error {
	if m.unfollow != nil {
		return m.unfollow(ctx, a, b)
	}
	return nil
}
func (m *mockFollowRepo) GetFollowers(ctx context.Context, id uuid.UUID, l, o int32) ([]uuid.UUID, int32, error) {
	if m.getFollowers != nil {
		return m.getFollowers(ctx, id, l, o)
	}
	return nil, 0, nil
}
func (m *mockFollowRepo) GetFollowing(context.Context, uuid.UUID, int32, int32) ([]uuid.UUID, int32, error) {
	return nil, 0, nil
}
func (m *mockFollowRepo) IsFollowing(ctx context.Context, a, b uuid.UUID) (bool, error) {
	if m.isFollowing != nil {
		return m.isFollowing(ctx, a, b)
	}
	return false, nil
}

func uc(p *mockProfileRepo, f *mockFollowRepo) *SocialUseCase {
	if p == nil {
		p = &mockProfileRepo{}
	}
	if f == nil {
		f = &mockFollowRepo{}
	}
	return NewSocialUseCase(p, f)
}

func TestGetProfile_Success(t *testing.T) {
	t.Parallel()

	want := &domain.UserProfile{UserID: uuid.New(), Username: "alice"}
	u := uc(&mockProfileRepo{
		getProfile: func(context.Context, uuid.UUID) (*domain.UserProfile, error) { return want, nil },
	}, nil)

	got, err := u.GetProfile(context.Background(), want.UserID)
	if err != nil || got.Username != "alice" {
		t.Fatalf("got (%v,%v), want (alice,nil)", got, err)
	}
}

func TestGetProfile_NotFound(t *testing.T) {
	t.Parallel()

	u := uc(&mockProfileRepo{
		getProfile: func(context.Context, uuid.UUID) (*domain.UserProfile, error) {
			return nil, domain.ErrProfileNotFound
		},
	}, nil)

	if _, err := u.GetProfile(context.Background(), uuid.New()); !errors.Is(err, domain.ErrProfileNotFound) {
		t.Fatalf("err = %v, want ErrProfileNotFound", err)
	}
}

func TestUpdateProfile_CallsUpsert(t *testing.T) {
	t.Parallel()

	called := false
	u := uc(&mockProfileRepo{
		upsertProfile: func(context.Context, domain.UserProfile) error { called = true; return nil },
	}, nil)

	if err := u.UpdateProfile(context.Background(), domain.UserProfile{UserID: uuid.New(), Username: "bob"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected UpsertProfile to be called")
	}
}

func TestFollowUser_PassesIDsThrough(t *testing.T) {
	t.Parallel()

	follower, followed := uuid.New(), uuid.New()
	var gotA, gotB uuid.UUID
	u := uc(nil, &mockFollowRepo{
		follow: func(_ context.Context, a, b uuid.UUID) error { gotA, gotB = a, b; return nil },
	})

	if err := u.FollowUser(context.Background(), follower, followed); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotA != follower || gotB != followed {
		t.Fatalf("repo got (%s,%s), want (%s,%s)", gotA, gotB, follower, followed)
	}
}

func TestFollowUser_AlreadyFollowing(t *testing.T) {
	t.Parallel()

	u := uc(nil, &mockFollowRepo{
		follow: func(context.Context, uuid.UUID, uuid.UUID) error { return domain.ErrAlreadyFollows },
	})

	if err := u.FollowUser(context.Background(), uuid.New(), uuid.New()); !errors.Is(err, domain.ErrAlreadyFollows) {
		t.Fatalf("err = %v, want ErrAlreadyFollows", err)
	}
}

func TestUnfollowUser_NotFollowing(t *testing.T) {
	t.Parallel()

	u := uc(nil, &mockFollowRepo{
		unfollow: func(context.Context, uuid.UUID, uuid.UUID) error { return domain.ErrNotFollowing },
	})

	if err := u.UnfollowUser(context.Background(), uuid.New(), uuid.New()); !errors.Is(err, domain.ErrNotFollowing) {
		t.Fatalf("err = %v, want ErrNotFollowing", err)
	}
}

func TestIsFollowing_True(t *testing.T) {
	t.Parallel()

	u := uc(nil, &mockFollowRepo{
		isFollowing: func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return true, nil },
	})

	ok, err := u.IsFollowing(context.Background(), uuid.New(), uuid.New())
	if err != nil || !ok {
		t.Fatalf("got (%v,%v), want (true,nil)", ok, err)
	}
}

func TestSearchUsers_ReturnsProfiles(t *testing.T) {
	t.Parallel()

	want := []domain.UserProfile{
		{UserID: uuid.New(), Username: "alice"},
		{UserID: uuid.New(), Username: "alicia"},
	}
	u := uc(&mockProfileRepo{
		searchProfiles: func(context.Context, string, int32, int32) ([]domain.UserProfile, int32, error) {
			return want, 2, nil
		},
	}, nil)

	got, total, err := u.SearchUsers(context.Background(), "ali", 20, 0)
	if err != nil || len(got) != 2 || total != 2 {
		t.Fatalf("got (%d,%d,%v), want (2,2,nil)", len(got), total, err)
	}
}

func TestSearchUsers_Empty(t *testing.T) {
	t.Parallel()

	got, total, err := uc(nil, nil).SearchUsers(context.Background(), "zzz", 20, 0)
	if err != nil || len(got) != 0 || total != 0 {
		t.Fatalf("got (%d,%d,%v), want (0,0,nil)", len(got), total, err)
	}
}

func TestGetFollowers_ReturnsList(t *testing.T) {
	t.Parallel()

	ids := []uuid.UUID{uuid.New(), uuid.New()}
	u := uc(nil, &mockFollowRepo{
		getFollowers: func(context.Context, uuid.UUID, int32, int32) ([]uuid.UUID, int32, error) {
			return ids, int32(len(ids)), nil
		},
	})

	got, total, err := u.GetFollowers(context.Background(), uuid.New(), 10, 0)
	if err != nil || len(got) != 2 || total != 2 {
		t.Fatalf("got (%d,%d,%v), want (2,2,nil)", len(got), total, err)
	}
}
