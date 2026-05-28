package domain

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type Person struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Surname   string    `json:"surname"`
	BirthYear int32     `json:"birth_year"`
}

func (p Person) Validate() error {
	if p.ID == uuid.Nil && (strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Surname) == "") {
		return ErrInvalidPerson
	}
	if p.BirthYear != 0 && (p.BirthYear < 1800 || p.BirthYear > int32(time.Now().Year())) {
		return ErrInvalidPerson
	}
	return nil
}
