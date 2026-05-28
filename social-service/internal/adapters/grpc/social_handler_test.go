package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/BigMoneyBigSuccess/cineMate/proto/social/socialv1"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/social-service/internal/core/usecase"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockProfileRepo struct {
	getProfile     func(context.Context, uuid.UUID) (*domain.UserProfile, error)
	upsertProfile  func(context.Context, domain.UserProfile) error
	searchProfiles func(context.Context, string, int32, int32) ([]domain.UserProfile, int32, error)
}

var _ ports.ProfileRepository = (*mockProfileRepo)(nil)

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
func (m *mockProfileRepo) SearchProfiles(ctx context.Context, query string, limit, offset int32) ([]domain.UserProfile, int32, error) {
	if m.searchProfiles != nil {
		return m.searchProfiles(ctx, query, limit, offset)
	}
	return nil, 0, nil
}

type mockFollowRepo struct {
	follow       func(context.Context, uuid.UUID, uuid.UUID) error
	unfollow     func(context.Context, uuid.UUID, uuid.UUID) error
	getFollowers func(context.Context, uuid.UUID, int32, int32) ([]uuid.UUID, int32, error)
	getFollowing func(context.Context, uuid.UUID, int32, int32) ([]uuid.UUID, int32, error)
	isFollowing  func(context.Context, uuid.UUID, uuid.UUID) (bool, error)
}

var _ ports.FollowRepository = (*mockFollowRepo)(nil)

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
func (m *mockFollowRepo) GetFollowing(ctx context.Context, id uuid.UUID, l, o int32) ([]uuid.UUID, int32, error) {
	if m.getFollowing != nil {
		return m.getFollowing(ctx, id, l, o)
	}
	return nil, 0, nil
}
func (m *mockFollowRepo) IsFollowing(ctx context.Context, a, b uuid.UUID) (bool, error) {
	if m.isFollowing != nil {
		return m.isFollowing(ctx, a, b)
	}
	return false, nil
}

func newHandler(profiles ports.ProfileRepository, follows ports.FollowRepository) *SocialHandler {
	return NewSocialHandler(usecase.NewSocialUseCase(profiles, follows))
}

func ctxWithUser(id uuid.UUID) context.Context {
	return context.WithValue(context.Background(), userIDContextKey, id)
}

func TestHandler_GetProfile_Success(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	h := newHandler(&mockProfileRepo{
		getProfile: func(_ context.Context, _ uuid.UUID) (*domain.UserProfile, error) {
			return &domain.UserProfile{UserID: id, Username: "alice"}, nil
		},
	}, &mockFollowRepo{})

	resp, err := h.GetProfile(context.Background(), &socialv1.GetProfileRequest{UserId: id.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Profile.Username != "alice" {
		t.Fatalf("got %q, want %q", resp.Profile.Username, "alice")
	}
}

func TestHandler_GetProfile_InvalidUUID(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockProfileRepo{}, &mockFollowRepo{})
	_, err := h.GetProfile(context.Background(), &socialv1.GetProfileRequest{UserId: "not-a-uuid"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
}

func TestHandler_GetProfile_NotFound(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockProfileRepo{
		getProfile: func(_ context.Context, _ uuid.UUID) (*domain.UserProfile, error) {
			return nil, domain.ErrProfileNotFound
		},
	}, &mockFollowRepo{})

	_, err := h.GetProfile(context.Background(), &socialv1.GetProfileRequest{UserId: uuid.New().String()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
}

func TestHandler_UpdateProfile_Success(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	var saved domain.UserProfile
	h := newHandler(&mockProfileRepo{
		upsertProfile: func(_ context.Context, p domain.UserProfile) error {
			saved = p
			return nil
		},
	}, &mockFollowRepo{})

	_, err := h.UpdateProfile(ctxWithUser(userID), &socialv1.UpdateProfileRequest{
		Username: "alice",
		Bio:      "loves movies",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if saved.UserID != userID || saved.Username != "alice" {
		t.Fatalf("profile not saved correctly: %+v", saved)
	}
}

func TestHandler_UpdateProfile_MissingUserID(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockProfileRepo{}, &mockFollowRepo{})
	_, err := h.UpdateProfile(context.Background(), &socialv1.UpdateProfileRequest{Username: "alice"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", err)
	}
}

func TestHandler_FollowUser_Success(t *testing.T) {
	t.Parallel()

	follower := uuid.New()
	followed := uuid.New()
	var gotA, gotB uuid.UUID

	h := newHandler(&mockProfileRepo{}, &mockFollowRepo{
		follow: func(_ context.Context, a, b uuid.UUID) error {
			gotA, gotB = a, b
			return nil
		},
	})

	_, err := h.FollowUser(ctxWithUser(follower), &socialv1.FollowUserRequest{FollowedId: followed.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotA != follower || gotB != followed {
		t.Fatalf("wrong args: got (%s,%s)", gotA, gotB)
	}
}

func TestHandler_FollowUser_AlreadyFollows(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockProfileRepo{}, &mockFollowRepo{
		follow: func(_ context.Context, _, _ uuid.UUID) error { return domain.ErrAlreadyFollows },
	})

	_, err := h.FollowUser(ctxWithUser(uuid.New()), &socialv1.FollowUserRequest{FollowedId: uuid.New().String()})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("got %v, want AlreadyExists", err)
	}
}

func TestHandler_IsFollowing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		result   bool
		wantBool bool
	}{
		{"following", true, true},
		{"not following", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler(&mockProfileRepo{}, &mockFollowRepo{
				isFollowing: func(_ context.Context, _, _ uuid.UUID) (bool, error) { return tc.result, nil },
			})

			resp, err := h.IsFollowing(context.Background(), &socialv1.IsFollowingRequest{
				FollowerId: uuid.New().String(),
				FollowedId: uuid.New().String(),
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.IsFollowing != tc.wantBool {
				t.Fatalf("got %v, want %v", resp.IsFollowing, tc.wantBool)
			}
		})
	}
}

func TestHandler_SearchUsers_Success(t *testing.T) {
	t.Parallel()

	profiles := []domain.UserProfile{
		{UserID: uuid.New(), Username: "alice"},
		{UserID: uuid.New(), Username: "alicia"},
	}
	h := newHandler(&mockProfileRepo{
		searchProfiles: func(_ context.Context, _ string, _, _ int32) ([]domain.UserProfile, int32, error) {
			return profiles, 2, nil
		},
	}, &mockFollowRepo{})

	resp, err := h.SearchUsers(context.Background(), &socialv1.SearchUsersRequest{Query: "ali", Limit: 20, Offset: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Profiles) != 2 || resp.Total != 2 {
		t.Fatalf("got %d profiles / total %d, want 2/2", len(resp.Profiles), resp.Total)
	}
	if resp.Profiles[0].Username != "alice" {
		t.Fatalf("got username %q, want %q", resp.Profiles[0].Username, "alice")
	}
}

func TestHandler_SearchUsers_Empty(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockProfileRepo{}, &mockFollowRepo{})

	resp, err := h.SearchUsers(context.Background(), &socialv1.SearchUsersRequest{Query: "zzz", Limit: 20, Offset: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Profiles) != 0 || resp.Total != 0 {
		t.Fatalf("expected empty result, got %d profiles", len(resp.Profiles))
	}
}

func TestMapSocialError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		code codes.Code
	}{
		{nil, codes.OK},
		{domain.ErrProfileNotFound, codes.NotFound},
		{domain.ErrAlreadyFollows, codes.AlreadyExists},
		{domain.ErrNotFollowing, codes.NotFound},
		{context.Canceled, codes.Canceled},
		{context.DeadlineExceeded, codes.DeadlineExceeded},
		{errors.New("unknown"), codes.Internal},
	}

	for _, tc := range cases {
		mapped := mapSocialError(tc.err)
		if status.Code(mapped) != tc.code {
			t.Errorf("mapSocialError(%v): got %s, want %s", tc.err, status.Code(mapped), tc.code)
		}
	}
}
