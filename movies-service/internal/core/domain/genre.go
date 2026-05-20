package domain

import (
	"strings"

	"github.com/google/uuid"
)

type Genre struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

func (g Genre) Validate() error {
	if g.ID == uuid.Nil && strings.TrimSpace(g.Name) == "" {
		return ErrInvalidGenre
	}
	return nil
}
