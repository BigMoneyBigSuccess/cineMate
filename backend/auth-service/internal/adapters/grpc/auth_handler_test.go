package grpc

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/BigMoneyBigSuccess/cineMate/proto/auth/authv1"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/utils"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (m *mockProfileCreator) CreateProfile(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

type mockBlacklist struct{}

func (m *mockBlacklist) Revoke(_ context.Context, _ string, _ time.Time) error { return nil }
func (m *mockBlacklist) IsRevoked(_ context.Context, _ string) (bool, error)   { return false, nil }

func newHandler(repo ports.UserRepository) *AuthHandler {
	return NewAuthHandler(usecase.NewAuthUseCase(repo, &mockProfileCreator{}, &mockBlacklist{}))
}

func TestHandler_Register_Success(t *testing.T) {
	t.Parallel()

	want := uuid.New()
	h := newHandler(&mockUserRepo{
		createUser: func(_ context.Context, _ domain.User) (uuid.UUID, error) { return want, nil },
	})

	resp, err := h.Register(context.Background(), &authv1.RegisterRequest{
		Email:    "user@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.UserId != want.String() {
		t.Fatalf("got %s, want %s", resp.UserId, want)
	}
}

func TestHandler_Register_NilRequest(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockUserRepo{})
	_, err := h.Register(context.Background(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
}

func TestHandler_Register_EmptyEmail(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockUserRepo{})
	_, err := h.Register(context.Background(), &authv1.RegisterRequest{Password: "password123"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
}

func TestHandler_Register_UserExists(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockUserRepo{
		createUser: func(_ context.Context, _ domain.User) (uuid.UUID, error) {
			return uuid.Nil, domain.ErrUserExists
		},
	})

	_, err := h.Register(context.Background(), &authv1.RegisterRequest{
		Email:    "user@example.com",
		Password: "password123",
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("got %v, want AlreadyExists", err)
	}
}

func TestHandler_Login_Success(t *testing.T) {
	t.Parallel()

	hash, _ := utils.HashPassword("password123")
	h := newHandler(&mockUserRepo{
		getUserByEmail: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: uuid.New(), Password: hash}, nil
		},
	})

	resp, err := h.Login(context.Background(), &authv1.LoginRequest{
		Email:    "user@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestHandler_Login_NotFound(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockUserRepo{
		getUserByEmail: func(_ context.Context, _ string) (*domain.User, error) { return nil, nil },
	})

	_, err := h.Login(context.Background(), &authv1.LoginRequest{
		Email:    "ghost@example.com",
		Password: "password123",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
}

func TestHandler_Login_WrongPassword(t *testing.T) {
	t.Parallel()

	hash, _ := utils.HashPassword("correct")
	h := newHandler(&mockUserRepo{
		getUserByEmail: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: uuid.New(), Password: hash}, nil
		},
	})

	_, err := h.Login(context.Background(), &authv1.LoginRequest{
		Email:    "user@example.com",
		Password: "wrong",
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("got %v, want Unauthenticated", err)
	}
}

func TestHandler_ValidateToken_Valid(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	token, _ := utils.GenerateJWT(id.String())
	h := newHandler(&mockUserRepo{})

	resp, err := h.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{Token: token})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("expected valid=true, error=%s", resp.Error)
	}
	if resp.UserId != id.String() {
		t.Fatalf("got %s, want %s", resp.UserId, id)
	}
}

func TestHandler_ValidateToken_Invalid(t *testing.T) {
	t.Parallel()

	h := newHandler(&mockUserRepo{})
	resp, err := h.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{Token: "bad.token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Fatal("expected valid=false")
	}
	if resp.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}
