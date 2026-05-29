package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPersonValidate(t *testing.T) {
	t.Parallel()

	currentYear := int32(time.Now().Year())

	tests := []struct {
		name    string
		person  Person
		wantErr error
	}{
		{
			name:    "id nil with both names filled",
			person:  Person{Name: "Tom", Surname: "Hanks"},
			wantErr: nil,
		},
		{
			name:    "id nil with both names and birth year",
			person:  Person{Name: "Tom", Surname: "Hanks", BirthYear: 1956},
			wantErr: nil,
		},
		{
			name:    "id set bypasses name requirement",
			person:  Person{ID: uuid.New()},
			wantErr: nil,
		},
		{
			name:    "id set with names is also valid",
			person:  Person{ID: uuid.New(), Name: "Tom", Surname: "Hanks"},
			wantErr: nil,
		},
		{
			name:    "id nil with empty name",
			person:  Person{Surname: "Hanks"},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "id nil with whitespace name",
			person:  Person{Name: "   ", Surname: "Hanks"},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "id nil with empty surname",
			person:  Person{Name: "Tom"},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "id nil with whitespace surname",
			person:  Person{Name: "Tom", Surname: "   "},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "id nil with both empty",
			person:  Person{},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "birth year zero is valid",
			person:  Person{Name: "Tom", Surname: "Hanks", BirthYear: 0},
			wantErr: nil,
		},
		{
			name:    "birth year at lower bound 1800",
			person:  Person{Name: "Tom", Surname: "Hanks", BirthYear: 1800},
			wantErr: nil,
		},
		{
			name:    "birth year below lower bound",
			person:  Person{Name: "Tom", Surname: "Hanks", BirthYear: 1799},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "birth year at current year",
			person:  Person{Name: "Tom", Surname: "Hanks", BirthYear: currentYear},
			wantErr: nil,
		},
		{
			name:    "birth year above current year",
			person:  Person{Name: "Tom", Surname: "Hanks", BirthYear: currentYear + 1},
			wantErr: ErrInvalidPerson,
		},
		{
			name:    "id set with invalid birth year still fails",
			person:  Person{ID: uuid.New(), BirthYear: 1799},
			wantErr: ErrInvalidPerson,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.person.Validate()
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
