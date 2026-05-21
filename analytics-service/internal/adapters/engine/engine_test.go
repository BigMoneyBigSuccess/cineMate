package engine

import (
	"context"
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
)

// mockMovieRepo is a test double for ports.MovieRepository.
type mockMovieRepo struct {
	getByIDFn    func(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error)
	listMoviesFn func(ctx context.Context, filter ports.MovieFilter) ([]domain.MovieSnapshot, error)
}

func (m *mockMovieRepo) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, id)
	}
	return nil, nil
}

func (m *mockMovieRepo) ListMovies(ctx context.Context, filter ports.MovieFilter) ([]domain.MovieSnapshot, error) {
	if m.listMoviesFn != nil {
		return m.listMoviesFn(ctx, filter)
	}
	return nil, nil
}

// --- rankCandidates ---

func TestRankCandidates_ExcludesFeedbackMovies(t *testing.T) {
	e := New(&mockMovieRepo{})
	seenID := uuid.New()
	freshID := uuid.New()

	candidates := []domain.MovieSnapshot{{MovieID: seenID}, {MovieID: freshID}}
	filter := ports.RecommendationFilter{
		Feedback: []domain.MovieFeedback{{MovieID: seenID}},
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:    10,
		Strategy: domain.StrategyGenresBased,
	}

	recs := e.rankCandidates(candidates, filter)
	if len(recs) != 1 {
		t.Fatalf("expected 1 rec, got %d", len(recs))
	}
	if *recs[0].MovieID != freshID {
		t.Error("feedback-seen movie should be excluded")
	}
}

func TestRankCandidates_ExcludesRecentRecommendations(t *testing.T) {
	e := New(&mockMovieRepo{})
	recentID := uuid.New()
	freshID := uuid.New()

	candidates := []domain.MovieSnapshot{{MovieID: recentID}, {MovieID: freshID}}
	filter := ports.RecommendationFilter{
		RecentRecommendations: []domain.MovieRecommendation{{MovieID: &recentID}},
		Profile:               domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:                 10,
		Strategy:              domain.StrategyGenresBased,
	}

	recs := e.rankCandidates(candidates, filter)
	if len(recs) != 1 {
		t.Fatalf("expected 1 rec, got %d", len(recs))
	}
	if *recs[0].MovieID != freshID {
		t.Error("recently-recommended movie should be excluded")
	}
}

func TestRankCandidates_RespectsLimit(t *testing.T) {
	e := New(&mockMovieRepo{})
	candidates := make([]domain.MovieSnapshot, 10)
	for i := range candidates {
		candidates[i] = domain.MovieSnapshot{MovieID: uuid.New()}
	}

	recs := e.rankCandidates(candidates, ports.RecommendationFilter{
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:    3,
		Strategy: domain.StrategyGenresBased,
	})
	if len(recs) != 3 {
		t.Fatalf("expected 3 recs, got %d", len(recs))
	}
}

func TestRankCandidates_AssignsRankSessionAndDefaults(t *testing.T) {
	e := New(&mockMovieRepo{})
	userID := uuid.New()
	candidates := []domain.MovieSnapshot{
		{MovieID: uuid.New()},
		{MovieID: uuid.New()},
		{MovieID: uuid.New()},
	}

	recs := e.rankCandidates(candidates, ports.RecommendationFilter{
		Profile:  domain.UserPreferenceProfile{UserID: userID},
		Limit:    3,
		Strategy: domain.StrategyGenresBased,
	})

	sessionID := recs[0].SessionID
	if sessionID == uuid.Nil {
		t.Fatal("session ID must not be nil")
	}
	for i, r := range recs {
		if r.Rank != i+1 {
			t.Errorf("rank[%d]: expected %d, got %d", i, i+1, r.Rank)
		}
		if r.SessionID != sessionID {
			t.Error("all recs must share the same session ID")
		}
		if r.UserID != userID {
			t.Errorf("UserID mismatch: expected %s, got %s", userID, r.UserID)
		}
		if r.Interaction != domain.InteractionTypeDismiss {
			t.Errorf("default interaction should be dismiss, got %q", r.Interaction)
		}
		if r.GeneratedAt.IsZero() {
			t.Error("GeneratedAt must be set")
		}
		if r.RecommendationID == uuid.Nil {
			t.Error("RecommendationID must not be nil")
		}
		if r.Strategy != domain.StrategyGenresBased {
			t.Errorf("strategy mismatch: expected genres_based, got %q", r.Strategy)
		}
	}
}

func TestRankCandidates_EmptyCandidates_ReturnsEmpty(t *testing.T) {
	e := New(&mockMovieRepo{})
	recs := e.rankCandidates(nil, ports.RecommendationFilter{
		Profile: domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:   5,
	})
	if len(recs) != 0 {
		t.Errorf("expected empty recs, got %d", len(recs))
	}
}

func TestRankCandidates_DeduplicatesAcrossBothSources(t *testing.T) {
	e := New(&mockMovieRepo{})
	fbMovieID := uuid.New()
	recMovieID := uuid.New()
	freshID := uuid.New()

	candidates := []domain.MovieSnapshot{
		{MovieID: fbMovieID},
		{MovieID: recMovieID},
		{MovieID: freshID},
	}
	filter := ports.RecommendationFilter{
		Feedback:              []domain.MovieFeedback{{MovieID: fbMovieID}},
		RecentRecommendations: []domain.MovieRecommendation{{MovieID: &recMovieID}},
		Profile:               domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:                 10,
	}

	recs := e.rankCandidates(candidates, filter)
	if len(recs) != 1 || *recs[0].MovieID != freshID {
		t.Errorf("only the unseen movie should appear, got %d recs", len(recs))
	}
}

// --- Recommend strategy routing ---

func TestRecommend_UnknownStrategy_ReturnsError(t *testing.T) {
	e := New(&mockMovieRepo{})
	_, err := e.Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.RecommendationStrategy("unknown_strategy"),
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:    5,
	})
	if err == nil {
		t.Fatal("expected error for unknown strategy")
	}
}

func TestRecommend_GenresBased_FiltersListMoviesByGenres(t *testing.T) {
	genreID := uuid.New()
	preferredGenres := []domain.Genre{{ID: genreID, Name: "Action"}}

	var capturedFilter ports.MovieFilter
	repo := &mockMovieRepo{
		listMoviesFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			capturedFilter = f
			return []domain.MovieSnapshot{{MovieID: uuid.New(), Genres: preferredGenres}}, nil
		},
	}

	_, err := New(repo).Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.StrategyGenresBased,
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New(), PreferredGenres: preferredGenres},
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(capturedFilter.Genres) != 1 || capturedFilter.Genres[0].ID != genreID {
		t.Error("ListMovies should be called with preferred genres")
	}
	if capturedFilter.SortBy != "imdb_rating" || capturedFilter.SortOrder != "desc" {
		t.Error("ListMovies should sort by imdb_rating desc")
	}
	if capturedFilter.Limit != candidateBuffer(2) {
		t.Errorf("limit should be candidateBuffer(2)=%d, got %d", candidateBuffer(2), capturedFilter.Limit)
	}
}

func TestRecommend_ActorsBased_FiltersListMoviesByActors(t *testing.T) {
	actorID := uuid.New()
	preferredActors := []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}}

	var capturedFilter ports.MovieFilter
	repo := &mockMovieRepo{
		listMoviesFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			capturedFilter = f
			return []domain.MovieSnapshot{{MovieID: uuid.New(), Actors: preferredActors}}, nil
		},
	}

	_, err := New(repo).Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.StrategyActorsBased,
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New(), PreferredActors: preferredActors},
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(capturedFilter.Actors) != 1 || capturedFilter.Actors[0].ID != actorID {
		t.Error("ListMovies should be called with preferred actors")
	}
}

func TestRecommend_DirectorsBased_FiltersListMoviesByDirectors(t *testing.T) {
	directorID := uuid.New()
	preferredDirectors := []domain.Person{{ID: directorID, Name: "Jane", Surname: "Smith"}}

	var capturedFilter ports.MovieFilter
	repo := &mockMovieRepo{
		listMoviesFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			capturedFilter = f
			return []domain.MovieSnapshot{{MovieID: uuid.New(), Directors: preferredDirectors}}, nil
		},
	}

	_, err := New(repo).Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.StrategyDirectorsBased,
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New(), PreferredDirectors: preferredDirectors},
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(capturedFilter.Directors) != 1 || capturedFilter.Directors[0].ID != directorID {
		t.Error("ListMovies should be called with preferred directors")
	}
}

func TestRecommend_ProfileBased_CascadesGenresThenActorsThenDirectors(t *testing.T) {
	genreID := uuid.New()
	actorID := uuid.New()

	var capturedFilters []ports.MovieFilter
	repo := &mockMovieRepo{
		listMoviesFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			capturedFilters = append(capturedFilters, f)
			return nil, nil // empty — forces all cascade steps + fallback
		},
	}

	profile := domain.UserPreferenceProfile{
		UserID:          uuid.New(),
		PreferredGenres: []domain.Genre{{ID: genreID, Name: "Action"}},
		PreferredActors: []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
	}

	_, err := New(repo).Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.StrategyPreferenceProfileBased,
		Profile:  profile,
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// genres → actors → fallback (top-rated), no directors (none in profile)
	if len(capturedFilters) < 3 {
		t.Fatalf("expected ≥3 ListMovies calls (genres, actors, fallback), got %d", len(capturedFilters))
	}
	if len(capturedFilters[0].Genres) == 0 {
		t.Error("first fetch should filter by genres")
	}
	if len(capturedFilters[1].Actors) == 0 {
		t.Error("second fetch should filter by actors")
	}
	// fallback call should have no genre/actor/director filter, sort by rating desc
	fallback := capturedFilters[len(capturedFilters)-1]
	if fallback.SortBy != "imdb_rating" || fallback.SortOrder != "desc" {
		t.Error("fallback fetch should sort by imdb_rating desc")
	}
}

func TestRecommend_ProfileBased_SkipsActorsFetchWhenPoolAlreadyFull(t *testing.T) {
	genreID := uuid.New()
	actorID := uuid.New()

	callCount := 0
	repo := &mockMovieRepo{
		listMoviesFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			callCount++
			if callCount == 1 {
				// First call (genres): return enough to fill the pool
				limit := candidateBuffer(2)
				movies := make([]domain.MovieSnapshot, limit)
				for i := range movies {
					movies[i] = domain.MovieSnapshot{MovieID: uuid.New()}
				}
				return movies, nil
			}
			return nil, nil
		},
	}

	profile := domain.UserPreferenceProfile{
		UserID:          uuid.New(),
		PreferredGenres: []domain.Genre{{ID: genreID, Name: "Action"}},
		PreferredActors: []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
	}

	_, err := New(repo).Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.StrategyPreferenceProfileBased,
		Profile:  profile,
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 ListMovies call when genres fill the pool, got %d", callCount)
	}
}

func TestRecommend_ReturnsRecsUpToLimit(t *testing.T) {
	movies := make([]domain.MovieSnapshot, 20)
	for i := range movies {
		movies[i] = domain.MovieSnapshot{MovieID: uuid.New()}
	}

	repo := &mockMovieRepo{
		listMoviesFn: func(_ context.Context, _ ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			return movies, nil
		},
	}

	recs, err := New(repo).Recommend(context.Background(), ports.RecommendationFilter{
		Strategy: domain.StrategyGenresBased,
		Profile:  domain.UserPreferenceProfile{UserID: uuid.New()},
		Limit:    5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 5 {
		t.Errorf("expected 5 recs, got %d", len(recs))
	}
}
