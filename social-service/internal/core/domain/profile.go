package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserProfile struct {
	UserID    uuid.UUID
	Username  string
	Bio       string
	CreatedAt time.Time
	UpdatedAt time.Time
}
