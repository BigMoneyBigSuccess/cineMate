package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
}

func (u User) Validate() error {
	email := strings.TrimSpace(u.Email)
	password := strings.TrimSpace(u.Password)
	if email == "" || password == "" {
		return ErrInvalidUser
	}
	if len(password) < 8 {
		return ErrInvalidUser
	}
	return nil
}
