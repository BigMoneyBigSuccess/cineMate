package usecase

import (
	"context"
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/adapters/engine"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
)

// movieCatalogStub is a configurable stub for ports.MovieRepository.
// The listFn is called on every ListMovies call; distinguish which fetch it is
// by inspecting the filter (Genres/Actors/Directors set vs. empty fallback).
type movieCatalogStub struct {
	listFn func(ctx context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error)
}

func (m *movieCatalogStub) ListMovies(ctx context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
	if m.listFn != nil {
		return m.listFn(ctx, f)
	}
	return nil, nil
}

func (m *movieCatalogStub) GetMovieByID(_ context.Context, _ uuid.UUID) (*domain.MovieSnapshot, error) {
	return nil, nil
}

// buildPipelineUC wires the real recommendation engine with stub repos.
// profileFn and feedbackFn can be nil; they default to empty profile / no feedback.
func buildPipelineUC(
	catalog ports.MovieRepository,
	profile domain.UserPreferenceProfile,
	feedback []domain.MovieFeedback,
	recentRecs []domain.MovieRecommendation,
) *RecommendationUseCase {
	profileRepo := &mockProfileRepo{
		getOrCreateFn: func(_ context.Context, _ uuid.UUID) (domain.UserPreferenceProfile, error) {
			return profile, nil
		},
	}
	feedbackRepo := &mockFeedbackRepo{
		listFn: func(_ context.Context, _ uuid.UUID) ([]domain.MovieFeedback, error) {
			return feedback, nil
		},
	}
	recRepo := &mockRecRepo{
		listFn: func(_ context.Context, _ uuid.UUID, _ ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
			return recentRecs, nil
		},
		saveBatchFn: func(_ context.Context, _ []domain.MovieRecommendation) error { return nil },
	}
	return NewRecommendationUseCase(profileRepo, feedbackRepo, recRepo, engine.New(catalog))
}

// TestPipeline_ProfileBased_ProfileMatchingMovieRanksFirst verifies that
// a movie matching the user's preferred genre and actor (IMDb 7.0, score 11.5)
// ranks above a higher-rated movie that matches no preferences (IMDb 9.0).
func TestPipeline_ProfileBased_ProfileMatchingMovieRanksFirst(t *testing.T) {
	userID := uuid.New()
	genreID := uuid.New()
	actorID := uuid.New()

	preferredMovieID := uuid.New()
	highRatedMovieID := uuid.New()

	preferredMovie := domain.MovieSnapshot{
		MovieID:    preferredMovieID,
		IMDbRating: 7.0,
		Genres:     []domain.Genre{{ID: genreID, Name: "Action"}},
		Actors:     []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
		Directors:  []domain.Person{{ID: uuid.New(), Name: "Some", Surname: "Director"}},
	}
	highRatedMovie := domain.MovieSnapshot{
		MovieID:    highRatedMovieID,
		IMDbRating: 9.0,
		Genres:     []domain.Genre{{ID: uuid.New(), Name: "Comedy"}},
		Actors:     []domain.Person{{ID: uuid.New(), Name: "Jane", Surname: "Smith"}},
		Directors:  []domain.Person{{ID: uuid.New(), Name: "Other", Surname: "Director"}},
	}

	// The engine fetches: (1) by genres, (2) by actors, (3) fallback top-rated.
	// preferredMovie appears in all three; highRatedMovie only in the fallback.
	catalog := &movieCatalogStub{
		listFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			switch {
			case len(f.Genres) > 0:
				return []domain.MovieSnapshot{preferredMovie}, nil
			case len(f.Actors) > 0:
				return []domain.MovieSnapshot{preferredMovie}, nil
			default: // fallback: top-rated
				return []domain.MovieSnapshot{highRatedMovie, preferredMovie}, nil
			}
		},
	}

	profile := domain.UserPreferenceProfile{
		UserID:          userID,
		PreferredGenres: []domain.Genre{{ID: genreID, Name: "Action"}},
		PreferredActors: []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
	}

	uc := buildPipelineUC(catalog, profile, nil, nil)

	recs, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID:   userID,
		Strategy: domain.StrategyPreferenceProfileBased,
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(recs))
	}
	// preferredMovie: 7.0 + 3.0 (genre) + 1.5 (actor) = 11.5
	// highRatedMovie: 9.0 (no profile match)
	if *recs[0].MovieID != preferredMovieID {
		t.Errorf("profile-matching movie should rank first (score 11.5 > 9.0); got %v first", recs[0].MovieID)
	}
	if *recs[1].MovieID != highRatedMovieID {
		t.Errorf("high-rated non-matching movie should rank second; got %v second", recs[1].MovieID)
	}
}

// TestPipeline_ProfileBased_AllThreeSignalsStack verifies that genre + actor +
// director boosts stack (5.0 + 3.0 + 1.5 + 1.5 = 11.0) and beat a near-perfect
// IMDb rating (9.5) that matches no preferences.
func TestPipeline_ProfileBased_AllThreeSignalsStack(t *testing.T) {
	userID := uuid.New()
	genreID := uuid.New()
	actorID := uuid.New()
	directorID := uuid.New()

	tripleMatchID := uuid.New()
	highIMDbID := uuid.New()

	tripleMatch := domain.MovieSnapshot{
		MovieID:    tripleMatchID,
		IMDbRating: 5.0,
		Genres:     []domain.Genre{{ID: genreID, Name: "Action"}},
		Actors:     []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
		Directors:  []domain.Person{{ID: directorID, Name: "Chris", Surname: "Nolan"}},
	}
	highIMDb := domain.MovieSnapshot{
		MovieID:    highIMDbID,
		IMDbRating: 9.5,
		Genres:     []domain.Genre{{ID: uuid.New(), Name: "Drama"}},
		Actors:     []domain.Person{{ID: uuid.New(), Name: "Jane", Surname: "Smith"}},
		Directors:  []domain.Person{{ID: uuid.New(), Name: "Other", Surname: "Director"}},
	}

	catalog := &movieCatalogStub{
		listFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			switch {
			case len(f.Genres) > 0:
				return []domain.MovieSnapshot{tripleMatch}, nil
			case len(f.Actors) > 0:
				return []domain.MovieSnapshot{tripleMatch}, nil
			case len(f.Directors) > 0:
				return []domain.MovieSnapshot{tripleMatch}, nil
			default: // fallback
				return []domain.MovieSnapshot{highIMDb, tripleMatch}, nil
			}
		},
	}

	profile := domain.UserPreferenceProfile{
		UserID:             userID,
		PreferredGenres:    []domain.Genre{{ID: genreID}},
		PreferredActors:    []domain.Person{{ID: actorID}},
		PreferredDirectors: []domain.Person{{ID: directorID}},
	}

	uc := buildPipelineUC(catalog, profile, nil, nil)

	recs, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID:   userID,
		Strategy: domain.StrategyPreferenceProfileBased,
		Limit:    1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	// tripleMatch: 5.0 + 3.0 + 1.5 + 1.5 = 11.0 > highIMDb: 9.5
	if *recs[0].MovieID != tripleMatchID {
		t.Errorf("triple-match movie (score 11.0) should beat high IMDb (9.5); got %v", recs[0].MovieID)
	}
}

// TestPipeline_ProfileBased_FeedbackSeenMovieExcluded verifies that a movie the
// user has already rated — even if it would score highest — is excluded from results.
func TestPipeline_ProfileBased_FeedbackSeenMovieExcluded(t *testing.T) {
	userID := uuid.New()
	genreID := uuid.New()
	actorID := uuid.New()

	seenMovieID := uuid.New()
	freshMovieID := uuid.New()

	seenMovie := domain.MovieSnapshot{
		MovieID:    seenMovieID,
		IMDbRating: 9.0,
		Genres:     []domain.Genre{{ID: genreID, Name: "Action"}},
		Actors:     []domain.Person{{ID: actorID, Name: "John", Surname: "Doe"}},
		Directors:  []domain.Person{{ID: uuid.New(), Name: "X", Surname: "Y"}},
	}
	freshMovie := domain.MovieSnapshot{
		MovieID:    freshMovieID,
		IMDbRating: 6.0,
		Genres:     []domain.Genre{{ID: uuid.New(), Name: "Comedy"}},
		Actors:     []domain.Person{{ID: uuid.New(), Name: "Jane", Surname: "Smith"}},
		Directors:  []domain.Person{{ID: uuid.New(), Name: "A", Surname: "B"}},
	}

	catalog := &movieCatalogStub{
		listFn: func(_ context.Context, f ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			switch {
			case len(f.Genres) > 0:
				return []domain.MovieSnapshot{seenMovie}, nil
			case len(f.Actors) > 0:
				return []domain.MovieSnapshot{seenMovie}, nil
			default:
				return []domain.MovieSnapshot{seenMovie, freshMovie}, nil
			}
		},
	}

	profile := domain.UserPreferenceProfile{
		UserID:          userID,
		PreferredGenres: []domain.Genre{{ID: genreID}},
		PreferredActors: []domain.Person{{ID: actorID}},
	}
	feedback := []domain.MovieFeedback{
		{FeedbackID: uuid.New(), UserID: userID, MovieID: seenMovieID, Rating: 9},
	}

	uc := buildPipelineUC(catalog, profile, feedback, nil)

	recs, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID:   userID,
		Strategy: domain.StrategyPreferenceProfileBased,
		Limit:    5,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation (seen movie excluded), got %d", len(recs))
	}
	if *recs[0].MovieID != freshMovieID {
		t.Errorf("only the unseen movie should appear; got %v", recs[0].MovieID)
	}
}

// TestPipeline_ProfileBased_EmptyProfileFallsBackToTopRated verifies that when the
// user has no recorded preferences the engine falls back to top-rated movies.
func TestPipeline_ProfileBased_EmptyProfileFallsBackToTopRated(t *testing.T) {
	userID := uuid.New()

	topMovieID := uuid.New()
	lowMovieID := uuid.New()

	// Empty profile → no genre/actor/director fetches; only fallback fires.
	catalog := &movieCatalogStub{
		listFn: func(_ context.Context, _ ports.MovieFilter) ([]domain.MovieSnapshot, error) {
			return []domain.MovieSnapshot{
				{
					MovieID:    topMovieID,
					IMDbRating: 9.5,
					Genres:     []domain.Genre{{ID: uuid.New(), Name: "Drama"}},
					Actors:     []domain.Person{{ID: uuid.New(), Name: "A", Surname: "B"}},
					Directors:  []domain.Person{{ID: uuid.New(), Name: "C", Surname: "D"}},
				},
				{
					MovieID:    lowMovieID,
					IMDbRating: 5.0,
					Genres:     []domain.Genre{{ID: uuid.New(), Name: "Comedy"}},
					Actors:     []domain.Person{{ID: uuid.New(), Name: "E", Surname: "F"}},
					Directors:  []domain.Person{{ID: uuid.New(), Name: "G", Surname: "H"}},
				},
			}, nil
		},
	}

	emptyProfile := domain.UserPreferenceProfile{UserID: userID}

	uc := buildPipelineUC(catalog, emptyProfile, nil, nil)

	recs, err := uc.GenerateRecommendations(context.Background(), RecommendationRequest{
		UserID:   userID,
		Strategy: domain.StrategyPreferenceProfileBased,
		Limit:    2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations, got %d", len(recs))
	}
	if *recs[0].MovieID != topMovieID {
		t.Errorf("top-rated movie should rank first when profile is empty; got %v", recs[0].MovieID)
	}
}
