package usecase

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/utils"
	"github.com/google/uuid"
)

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "test-secret-key-at-least-32-chars!!")
	if err := utils.LoadJWTSecret(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

type mockUserRepo struct {
	createUser     func(context.Context, domain.User) (uuid.UUID, error)
	getUserByEmail func(context.Context, string) (*domain.User, error)
}

var _ ports.UserRepository = (*mockUserRepo)(nil)

func (m *mockUserRepo) CreateUser(ctx context.Context, u domain.User) (uuid.UUID, error) {
	if m.createUser != nil {
		return m.createUser(ctx, u)
	}
	return uuid.Nil, nil
}
func (m *mockUserRepo) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.getUserByEmail != nil {
		return m.getUserByEmail(ctx, email)
	}
	return nil, nil
}

type mockProfileCreator struct{}

var _ ports.ProfileCreator = (*mockProfileCreator)(nil)

func (m *mockProfileCreator) CreateProfile(context.Context, uuid.UUID, string) error { return nil }

type mockBlacklist struct {
	isRevoked func(context.Context, string) (bool, error)
}

var _ ports.TokenBlacklist = (*mockBlacklist)(nil)

func (m *mockBlacklist) Revoke(context.Context, string, time.Time) error { return nil }
func (m *mockBlacklist) IsRevoked(ctx context.Context, hash string) (bool, error) {
	if m.isRevoked != nil {
		return m.isRevoked(ctx, hash)
	}
	return false, nil
}

var (
	noopSocial    = &mockProfileCreator{}
	noopBlacklist = &mockBlacklist{}
)

// returnID makes a CreateUser stub that always returns id.
func returnID(id uuid.UUID) func(context.Context, domain.User) (uuid.UUID, error) {
	return func(context.Context, domain.User) (uuid.UUID, error) { return id, nil }
}

// returnUser makes a GetUserByEmail stub that always returns u.
func returnUser(u *domain.User) func(context.Context, string) (*domain.User, error) {
	return func(context.Context, string) (*domain.User, error) { return u, nil }
}

func TestRegister(t *testing.T) {
	t.Parallel()

	wantID := uuid.New()
	boom := errors.New("db error")

	tests := []struct {
		name     string
		email    string
		password string
		repo     *mockUserRepo
		wantErr  error
	}{
		{"success", "user@example.com", "password123", &mockUserRepo{createUser: returnID(wantID)}, nil},
		{"empty email rejected", "", "password123", &mockUserRepo{}, domain.ErrInvalidUser},
		{"short password rejected", "user@example.com", "short", &mockUserRepo{}, domain.ErrInvalidUser},
		{"repo error propagates", "user@example.com", "password123",
			&mockUserRepo{createUser: func(context.Context, domain.User) (uuid.UUID, error) { return uuid.Nil, boom }},
			boom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uc := NewAuthUseCase(tt.repo, noopSocial, noopBlacklist)

			got, err := uc.Register(context.Background(), tt.email, tt.password)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != wantID {
				t.Fatalf("got %s, want %s", got, wantID)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	hash, _ := utils.HashPassword("secret123!")
	storedUser := &domain.User{ID: id, Email: "user@example.com", Password: hash}

	tests := []struct {
		name     string
		password string
		repo     *mockUserRepo
		wantErr  error
	}{
		{"success", "secret123!", &mockUserRepo{getUserByEmail: returnUser(storedUser)}, nil},
		{"user not found", "password123", &mockUserRepo{getUserByEmail: returnUser(nil)}, domain.ErrUserNotFound},
		{"wrong password", "wrong", &mockUserRepo{getUserByEmail: returnUser(storedUser)}, domain.ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			uc := NewAuthUseCase(tt.repo, noopSocial, noopBlacklist)

			token, err := uc.Login(context.Background(), "user@example.com", tt.password)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token == "" {
				t.Fatal("expected non-empty token")
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	validToken, _ := utils.GenerateJWT(id.String())

	t.Run("valid token returns user id", func(t *testing.T) {
		t.Parallel()
		uc := NewAuthUseCase(&mockUserRepo{}, noopSocial, noopBlacklist)

		got, err := uc.ValidateToken(context.Background(), validToken)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != id {
			t.Fatalf("got %s, want %s", got, id)
		}
	})

	t.Run("invalid token returns error", func(t *testing.T) {
		t.Parallel()
		uc := NewAuthUseCase(&mockUserRepo{}, noopSocial, noopBlacklist)

		if _, err := uc.ValidateToken(context.Background(), "bad.token.value"); err == nil {
			t.Fatal("expected error for invalid token")
		}
	})
}
