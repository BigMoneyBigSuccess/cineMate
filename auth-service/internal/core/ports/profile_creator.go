package ports

import (
	"context"

	"github.com/google/uuid"
)

type ProfileCreator interface {
	CreateProfile(ctx context.Context, userID uuid.UUID, username string) error
}
