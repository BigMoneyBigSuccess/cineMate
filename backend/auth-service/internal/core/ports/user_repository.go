package ports

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/domain"
	"github.com/google/uuid"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user domain.User) (uuid.UUID, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
}
