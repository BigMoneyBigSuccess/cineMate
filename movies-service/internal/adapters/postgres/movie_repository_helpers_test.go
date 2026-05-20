package postgres

import (
	"fmt"
	"github.com/BigMoneyBigSuccess/cineMate/movies-service/internal/core/domain"
	"strings"
	"testing"
)

func TestBuildPersonFilterClauseUsesStructuredFields(t *testing.T) {
	t.Parallel()

	var args []any
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	clause := buildPersonFilterClause("movie_actors", "ma", []domain.Person{
		{Name: "Tom", Surname: "Hanks", BirthYear: 1956},
	}, addArg)

	for _, expected := range []string{"p.name = $1", "p.surname = $2", "p.birth_year = $3"} {
		if !strings.Contains(clause, expected) {
			t.Fatalf("expected clause to contain %q, got %q", expected, clause)
		}
	}
	if len(args) != 3 {
		t.Fatalf("unexpected args length: got %d want 3", len(args))
	}
}

func TestBuildPersonFilterClauseSupportsPartialPersonFilters(t *testing.T) {
	t.Parallel()

	addArg := func(value any) string {
		return "$1"
	}

	clause := buildPersonFilterClause("movie_directors", "md", []domain.Person{
		{Name: "Christopher"},
	}, addArg)

	if !strings.Contains(clause, "p.name = $1") {
		t.Fatalf("expected clause to filter by person name, got %q", clause)
	}
	if strings.Contains(clause, "concat_ws") {
		t.Fatalf("expected structured field filtering, got legacy display-name clause %q", clause)
	}
}
