package domain

import "github.com/google/uuid"

type Genre struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

func (g Genre) Validate() error {
	if val, err := g.ID.Value(); err != nil || val == nil {
		return ErrInvalidGenre
	}
	if g.Name == "" {
		return ErrInvalidGenre
	}
	return nil
}
