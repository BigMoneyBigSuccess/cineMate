package domain

import (
	"time"

	"github.com/google/uuid"
)

type Follow struct {
	FollowerID uuid.UUID
	FollowedID uuid.UUID
	CreatedAt  time.Time
}
