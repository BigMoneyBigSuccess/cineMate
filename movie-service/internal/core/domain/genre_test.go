package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestGenreValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		genre   Genre
		wantErr error
	}{
		{
			name:    "id nil with name",
			genre:   Genre{Name: "Drama"},
			wantErr: nil,
		},
		{
			name:    "id set with no name",
			genre:   Genre{ID: uuid.New()},
			wantErr: nil,
		},
		{
			name:    "id set with name",
			genre:   Genre{ID: uuid.New(), Name: "Action"},
			wantErr: nil,
		},
		{
			name:    "id nil with empty name",
			genre:   Genre{},
			wantErr: ErrInvalidGenre,
		},
		{
			name:    "id nil with whitespace-only name",
			genre:   Genre{Name: "   "},
			wantErr: ErrInvalidGenre,
		},
		{
			name:    "id nil with tab whitespace name",
			genre:   Genre{Name: "\t"},
			wantErr: ErrInvalidGenre,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.genre.Validate()
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
