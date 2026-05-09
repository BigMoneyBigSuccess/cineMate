package domain

import (
	"time"

	"github.com/google/uuid"
)

type Person struct {
	ID        uuid.UUID
	Name      string
	Surname   string
	BirthYear int32
}

func (p Person) Validate() error {
	if val, err := p.ID.Value(); err != nil || val == nil {
		return ErrInvalidPerson
	}
	if p.Name == "" || p.Surname == "" {
		return ErrInvalidPerson
	}
	if p.BirthYear < 1800 || p.BirthYear > int32(time.Now().Year()) {
		return ErrInvalidPerson
	}
	return nil
}
