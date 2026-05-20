package postgres

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
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

// ── buildPersonFilterClause ───────────────────────────────────────────────────

func TestBuildPersonFilterClauseEmptyPeopleReturnsEmpty(t *testing.T) {
	t.Parallel()

	addArg := func(value any) string { return "$1" }
	clause := buildPersonFilterClause("movie_actors", "ma", nil, addArg)
	if clause != "" {
		t.Fatalf("expected empty clause for nil people, got %q", clause)
	}

	clause2 := buildPersonFilterClause("movie_actors", "ma", []domain.Person{}, addArg)
	if clause2 != "" {
		t.Fatalf("expected empty clause for empty people slice, got %q", clause2)
	}
}

func TestBuildPersonFilterClauseByIDSkipsNameFields(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	var args []any
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	clause := buildPersonFilterClause("movie_actors", "ma", []domain.Person{
		{ID: id, Name: "Tom", Surname: "Hanks"},
	}, addArg)

	// When ID is set, only p.id filter should be used
	if !strings.Contains(clause, "p.id = $1") {
		t.Fatalf("expected p.id filter, got %q", clause)
	}
	if strings.Contains(clause, "p.name") {
		t.Fatalf("expected no p.name filter when ID is set, got %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg (id), got %d", len(args))
	}
}

func TestBuildPersonFilterClauseSurnameOnlyField(t *testing.T) {
	t.Parallel()

	var args []any
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	clause := buildPersonFilterClause("movie_actors", "ma", []domain.Person{
		{Surname: "Spielberg"},
	}, addArg)

	if !strings.Contains(clause, "p.surname = $1") {
		t.Fatalf("expected p.surname filter, got %q", clause)
	}
	if strings.Contains(clause, "p.name") {
		t.Fatalf("expected no p.name filter for surname-only person, got %q", clause)
	}
}

func TestBuildPersonFilterClauseMultiplePeopleJoinedWithOR(t *testing.T) {
	t.Parallel()

	n := 0
	addArg := func(value any) string {
		n++
		return fmt.Sprintf("$%d", n)
	}

	clause := buildPersonFilterClause("movie_actors", "ma", []domain.Person{
		{Name: "Tom", Surname: "Hanks"},
		{Name: "Brad", Surname: "Pitt"},
	}, addArg)

	if strings.Count(clause, "p.name") != 2 {
		t.Fatalf("expected 2 name conditions in clause, got %q", clause)
	}
	if !strings.Contains(clause, " OR ") {
		t.Fatalf("expected OR between person conditions, got %q", clause)
	}
}

// ── buildGenreFilterClause ────────────────────────────────────────────────────

func TestBuildGenreFilterClauseEmpty(t *testing.T) {
	t.Parallel()

	addArg := func(value any) string { return "$1" }

	if clause := buildGenreFilterClause(nil, addArg); clause != "" {
		t.Fatalf("expected empty clause for nil genres, got %q", clause)
	}
	if clause := buildGenreFilterClause([]domain.Genre{}, addArg); clause != "" {
		t.Fatalf("expected empty clause for empty genres, got %q", clause)
	}
}

func TestBuildGenreFilterClauseByIDOnly(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	var args []any
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	clause := buildGenreFilterClause([]domain.Genre{{ID: id}}, addArg)

	if !strings.Contains(clause, "g.id IN ($1)") {
		t.Fatalf("expected g.id IN clause, got %q", clause)
	}
	if strings.Contains(clause, "g.name") {
		t.Fatalf("expected no g.name filter when only ID provided, got %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
}

func TestBuildGenreFilterClauseByNameOnly(t *testing.T) {
	t.Parallel()

	var args []any
	addArg := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}

	clause := buildGenreFilterClause([]domain.Genre{{Name: "Drama"}}, addArg)

	if !strings.Contains(clause, "g.name IN ($1)") {
		t.Fatalf("expected g.name IN clause, got %q", clause)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
}

func TestBuildGenreFilterClauseByIDAndNameBothPresent(t *testing.T) {
	t.Parallel()

	id := uuid.New()
	n := 0
	addArg := func(value any) string {
		n++
		return fmt.Sprintf("$%d", n)
	}

	clause := buildGenreFilterClause([]domain.Genre{{ID: id, Name: "Drama"}}, addArg)

	if !strings.Contains(clause, "g.id IN") {
		t.Fatalf("expected g.id IN clause, got %q", clause)
	}
	if !strings.Contains(clause, "g.name IN") {
		t.Fatalf("expected g.name IN clause, got %q", clause)
	}
	if !strings.Contains(clause, " OR ") {
		t.Fatalf("expected OR between id and name conditions, got %q", clause)
	}
}

func TestBuildGenreFilterClauseMultipleGenresCollected(t *testing.T) {
	t.Parallel()

	id1, id2 := uuid.New(), uuid.New()
	n := 0
	addArg := func(value any) string {
		n++
		return fmt.Sprintf("$%d", n)
	}

	clause := buildGenreFilterClause([]domain.Genre{
		{ID: id1},
		{ID: id2},
	}, addArg)

	if !strings.Contains(clause, "$1, $2") {
		t.Fatalf("expected two placeholders in IN clause, got %q", clause)
	}
}

// ── buildMovieOrderBy ─────────────────────────────────────────────────────────

func TestBuildMovieOrderByKnownColumns(t *testing.T) {
	t.Parallel()

	knownCases := []struct {
		sortBy   string
		expected string
	}{
		{"title", "m.title"},
		{"release_year", "m.release_year"},
		{"imdb_rating", "m.imdb_rating"},
		{"country", "m.country"},
		{"source", "m.source"},
		{"last_sync_at", "m.last_sync_at"},
		{"id", "m.id"},
		{"movie_id", "m.id"},
		{"archived_at", "m.archived_at"},
	}

	for _, tc := range knownCases {
		tc := tc
		t.Run(tc.sortBy, func(t *testing.T) {
			t.Parallel()
			clause := buildMovieOrderBy(tc.sortBy, "asc")
			if !strings.Contains(clause, tc.expected) {
				t.Errorf("sortBy=%q: expected %q in %q", tc.sortBy, tc.expected, clause)
			}
		})
	}
}

func TestBuildMovieOrderByUnknownColumnDefaultsToTitle(t *testing.T) {
	t.Parallel()

	clause := buildMovieOrderBy("unknown_column", "asc")
	if !strings.Contains(clause, "m.title") {
		t.Fatalf("expected default m.title, got %q", clause)
	}
}

func TestBuildMovieOrderByEmptySortByDefaultsToTitle(t *testing.T) {
	t.Parallel()

	clause := buildMovieOrderBy("", "asc")
	if !strings.Contains(clause, "m.title") {
		t.Fatalf("expected default m.title for empty sortBy, got %q", clause)
	}
}

func TestBuildMovieOrderBySortOrderCaseInsensitive(t *testing.T) {
	t.Parallel()

	for _, order := range []string{"DESC", "desc", "Desc"} {
		clause := buildMovieOrderBy("title", order)
		if !strings.Contains(clause, "DESC") {
			t.Errorf("order=%q: expected DESC in %q", order, clause)
		}
	}
}

func TestBuildMovieOrderByDefaultsToASC(t *testing.T) {
	t.Parallel()

	for _, order := range []string{"asc", "ASC", "", "invalid"} {
		clause := buildMovieOrderBy("title", order)
		if strings.Contains(clause, "DESC") {
			t.Errorf("order=%q: expected ASC, got DESC in %q", order, clause)
		}
		if !strings.Contains(clause, "ASC") {
			t.Errorf("order=%q: expected ASC in %q", order, clause)
		}
	}
}

func TestBuildMovieOrderByAlwaysAppendsPrimaryTieBreaker(t *testing.T) {
	t.Parallel()

	clause := buildMovieOrderBy("title", "asc")
	if !strings.Contains(clause, "m.id ASC") {
		t.Fatalf("expected secondary m.id ASC tiebreaker in %q", clause)
	}
}

// ── personDisplayNameExpr ─────────────────────────────────────────────────────

func TestPersonDisplayNameExpr(t *testing.T) {
	t.Parallel()

	expr := personDisplayNameExpr("p")
	if !strings.Contains(expr, "concat_ws") {
		t.Errorf("expected concat_ws in expr, got %q", expr)
	}
	if !strings.Contains(expr, "p.name") {
		t.Errorf("expected p.name in expr, got %q", expr)
	}
	if !strings.Contains(expr, "p.surname") {
		t.Errorf("expected p.surname in expr, got %q", expr)
	}

	expr2 := personDisplayNameExpr("ma")
	if !strings.Contains(expr2, "ma.name") || !strings.Contains(expr2, "ma.surname") {
		t.Errorf("alias not applied correctly: %q", expr2)
	}
}
