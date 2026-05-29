package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/usecase"
	"github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ── mock repositories ─────────────────────────────────────────────────────────

type mockMovieRepo struct {
	upsertErr   error
	archiveErr  error
	removeErr   error
	getMovie    *domain.Movie
	getErr      error
	listMovies  []domain.Movie
	listErr     error
}

func (m *mockMovieRepo) UpsertMovie(_ context.Context, _ domain.Movie) error {
	return m.upsertErr
}
func (m *mockMovieRepo) ArchiveMovie(_ context.Context, _ uuid.UUID) error {
	return m.archiveErr
}
func (m *mockMovieRepo) RemoveMovie(_ context.Context, _ uuid.UUID) error {
	return m.removeErr
}
func (m *mockMovieRepo) GetMovieByID(_ context.Context, _ uuid.UUID) (*domain.Movie, error) {
	return m.getMovie, m.getErr
}
func (m *mockMovieRepo) ListMovies(_ context.Context, _ ports.MovieFilter) ([]domain.Movie, error) {
	return m.listMovies, m.listErr
}

type mockWatchlistRepo struct {
	addErr    error
	removeErr error
	movies    []domain.Movie
	getErr    error
}

func (m *mockWatchlistRepo) AddMovie(_ context.Context, _, _ uuid.UUID) error {
	return m.addErr
}
func (m *mockWatchlistRepo) RemoveMovie(_ context.Context, _, _ uuid.UUID) error {
	return m.removeErr
}
func (m *mockWatchlistRepo) GetUserWatchlist(_ context.Context, _ uuid.UUID) ([]domain.Movie, error) {
	return m.movies, m.getErr
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newHandler(movieRepo ports.MovieRepository, watchlistRepo ports.WatchlistRepository) *MovieHandler {
	return NewMovieHandler(
		usecase.NewMovieUseCase(movieRepo),
		usecase.NewWatchlistUseCase(watchlistRepo),
	)
}

func validProtoMovie() *movieservicev1.Movie {
	return &movieservicev1.Movie{
		Title:       "The Shawshank Redemption",
		Description: "A story of hope.",
		Country:     "USA",
		ReleaseYear: 1994,
		ImdbRating:  9.3,
		Genres:      []*movieservicev1.Genre{{Name: "Drama"}},
		Actors:      []*movieservicev1.Person{{Name: "Tim", Surname: "Robbins"}},
		Directors:   []*movieservicev1.Person{{Name: "Frank", Surname: "Darabont"}},
	}
}

func validDomainMovie() domain.Movie {
	return domain.Movie{
		MovieID:       uuid.New(),
		Title:         "The Shawshank Redemption",
		Description:   "A story of hope.",
		Country:       "USA",
		ReleaseYear:   1994,
		IMDbRating:    9.3,
		Source:        "manual",
		SourceMovieID: uuid.New().String(),
		Genres:        []domain.Genre{{Name: "Drama"}},
		Actors:        []domain.Person{{Name: "Tim", Surname: "Robbins"}},
		Directors:     []domain.Person{{Name: "Frank", Surname: "Darabont"}},
	}
}

func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if want == codes.OK {
		if err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("got code %v, want %v (err: %v)", got, want, err)
	}
}

// ── GetMovieByID ──────────────────────────────────────────────────────────────

func TestGetMovieByID_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.GetMovieByID(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestGetMovieByID_EmptyMovieID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.GetMovieByID(context.Background(), &movieservicev1.GetMovieByIDRequest{MovieId: ""})
	requireCode(t, err, codes.InvalidArgument)
}

func TestGetMovieByID_InvalidUUID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.GetMovieByID(context.Background(), &movieservicev1.GetMovieByIDRequest{MovieId: "not-a-uuid"})
	requireCode(t, err, codes.InvalidArgument)
}

func TestGetMovieByID_NotFound(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{getErr: pgx.ErrNoRows}, &mockWatchlistRepo{})
	_, err := h.GetMovieByID(context.Background(), &movieservicev1.GetMovieByIDRequest{MovieId: uuid.New().String()})
	requireCode(t, err, codes.NotFound)
}

func TestGetMovieByID_InternalError(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{getErr: errors.New("db down")}, &mockWatchlistRepo{})
	_, err := h.GetMovieByID(context.Background(), &movieservicev1.GetMovieByIDRequest{MovieId: uuid.New().String()})
	requireCode(t, err, codes.Internal)
}

func TestGetMovieByID_Success(t *testing.T) {
	t.Parallel()
	movie := validDomainMovie()
	h := newHandler(&mockMovieRepo{getMovie: &movie}, &mockWatchlistRepo{})
	resp, err := h.GetMovieByID(context.Background(), &movieservicev1.GetMovieByIDRequest{MovieId: movie.MovieID.String()})
	requireCode(t, err, codes.OK)
	if resp.GetMovie().GetMovieId() != movie.MovieID.String() {
		t.Errorf("MovieId = %q, want %q", resp.GetMovie().GetMovieId(), movie.MovieID.String())
	}
}

// ── ListMovies ────────────────────────────────────────────────────────────────

func TestListMovies_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ListMovies(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestListMovies_NegativeLimit(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ListMovies(context.Background(), &movieservicev1.ListMoviesRequest{Limit: -1})
	requireCode(t, err, codes.InvalidArgument)
}

func TestListMovies_NegativeOffset(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ListMovies(context.Background(), &movieservicev1.ListMoviesRequest{Offset: -1})
	requireCode(t, err, codes.InvalidArgument)
}

func TestListMovies_YearRangeInvalid(t *testing.T) {
	t.Parallel()
	from, to := int32(2020), int32(2010)
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ListMovies(context.Background(), &movieservicev1.ListMoviesRequest{
		ReleaseYearFrom: &from,
		ReleaseYearTo:   &to,
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestListMovies_RepoError(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{listErr: errors.New("db down")}, &mockWatchlistRepo{})
	_, err := h.ListMovies(context.Background(), &movieservicev1.ListMoviesRequest{})
	requireCode(t, err, codes.Internal)
}

func TestListMovies_Success(t *testing.T) {
	t.Parallel()
	movies := []domain.Movie{validDomainMovie(), validDomainMovie()}
	h := newHandler(&mockMovieRepo{listMovies: movies}, &mockWatchlistRepo{})
	resp, err := h.ListMovies(context.Background(), &movieservicev1.ListMoviesRequest{Limit: 10})
	requireCode(t, err, codes.OK)
	if len(resp.GetMovies()) != 2 {
		t.Errorf("len(movies) = %d, want 2", len(resp.GetMovies()))
	}
}

func TestListMovies_EmptyResult(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{listMovies: nil}, &mockWatchlistRepo{})
	resp, err := h.ListMovies(context.Background(), &movieservicev1.ListMoviesRequest{})
	requireCode(t, err, codes.OK)
	if len(resp.GetMovies()) != 0 {
		t.Errorf("expected empty movies list, got %d", len(resp.GetMovies()))
	}
}

// ── UpsertMovie ───────────────────────────────────────────────────────────────

func TestUpsertMovie_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.UpsertMovie(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestUpsertMovie_NilMovie(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.UpsertMovie(context.Background(), &movieservicev1.UpsertMovieRequest{Movie: nil})
	requireCode(t, err, codes.InvalidArgument)
}

func TestUpsertMovie_InvalidMovieUUID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	proto := validProtoMovie()
	proto.MovieId = "not-a-uuid"
	_, err := h.UpsertMovie(context.Background(), &movieservicev1.UpsertMovieRequest{Movie: proto})
	requireCode(t, err, codes.InvalidArgument)
}

func TestUpsertMovie_ValidationFails(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	proto := validProtoMovie()
	proto.Title = ""
	_, err := h.UpsertMovie(context.Background(), &movieservicev1.UpsertMovieRequest{Movie: proto})
	requireCode(t, err, codes.InvalidArgument)
}

func TestUpsertMovie_RepoError(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{upsertErr: errors.New("db down")}, &mockWatchlistRepo{})
	_, err := h.UpsertMovie(context.Background(), &movieservicev1.UpsertMovieRequest{Movie: validProtoMovie()})
	requireCode(t, err, codes.Internal)
}

func TestUpsertMovie_Success(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.UpsertMovie(context.Background(), &movieservicev1.UpsertMovieRequest{Movie: validProtoMovie()})
	requireCode(t, err, codes.OK)
}

func TestUpsertMovie_SetsManualSourceWhenMissing(t *testing.T) {
	t.Parallel()

	var captured domain.Movie
	capturingRepo := &capturingMovieRepo{
		onUpsert: func(m domain.Movie) error {
			captured = m
			return nil
		},
	}

	h := newHandler(capturingRepo, &mockWatchlistRepo{})
	proto := validProtoMovie() // protoToMovie never sets Source, so handler always sets "manual"

	_, err := h.UpsertMovie(context.Background(), &movieservicev1.UpsertMovieRequest{Movie: proto})
	requireCode(t, err, codes.OK)

	if captured.Source != "manual" {
		t.Errorf("Source = %q, want %q", captured.Source, "manual")
	}
	if captured.MovieID == uuid.Nil {
		t.Error("MovieID should be auto-generated")
	}
	if captured.SourceMovieID == "" {
		t.Error("SourceMovieID should be set to MovieID string")
	}
}

// ── ArchiveMovie ──────────────────────────────────────────────────────────────

func TestArchiveMovie_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ArchiveMovie(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestArchiveMovie_InvalidUUID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ArchiveMovie(context.Background(), &movieservicev1.ArchiveMovieRequest{MovieId: "bad"})
	requireCode(t, err, codes.InvalidArgument)
}

func TestArchiveMovie_RepoError(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{archiveErr: errors.New("db error")}, &mockWatchlistRepo{})
	_, err := h.ArchiveMovie(context.Background(), &movieservicev1.ArchiveMovieRequest{MovieId: uuid.New().String()})
	requireCode(t, err, codes.Internal)
}

func TestArchiveMovie_Success(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.ArchiveMovie(context.Background(), &movieservicev1.ArchiveMovieRequest{MovieId: uuid.New().String()})
	requireCode(t, err, codes.OK)
}

// ── RemoveMovie ───────────────────────────────────────────────────────────────

func TestRemoveMovie_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovie(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestRemoveMovie_InvalidUUID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovie(context.Background(), &movieservicev1.RemoveMovieRequest{MovieId: "bad"})
	requireCode(t, err, codes.InvalidArgument)
}

func TestRemoveMovie_NotFound(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{removeErr: pgx.ErrNoRows}, &mockWatchlistRepo{})
	_, err := h.RemoveMovie(context.Background(), &movieservicev1.RemoveMovieRequest{MovieId: uuid.New().String()})
	requireCode(t, err, codes.NotFound)
}

func TestRemoveMovie_Success(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovie(context.Background(), &movieservicev1.RemoveMovieRequest{MovieId: uuid.New().String()})
	requireCode(t, err, codes.OK)
}

// ── AddMovieToWatchlist ───────────────────────────────────────────────────────

func TestAddMovieToWatchlist_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.AddMovieToWatchlist(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestAddMovieToWatchlist_InvalidUserID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.AddMovieToWatchlist(context.Background(), &movieservicev1.AddMovieToWatchlistRequest{
		UserId:  "bad",
		MovieId: uuid.New().String(),
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestAddMovieToWatchlist_InvalidMovieID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.AddMovieToWatchlist(context.Background(), &movieservicev1.AddMovieToWatchlistRequest{
		UserId:  uuid.New().String(),
		MovieId: "bad",
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestAddMovieToWatchlist_RepoError(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{addErr: errors.New("conflict")})
	_, err := h.AddMovieToWatchlist(context.Background(), &movieservicev1.AddMovieToWatchlistRequest{
		UserId:  uuid.New().String(),
		MovieId: uuid.New().String(),
	})
	requireCode(t, err, codes.Internal)
}

func TestAddMovieToWatchlist_Success(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.AddMovieToWatchlist(context.Background(), &movieservicev1.AddMovieToWatchlistRequest{
		UserId:  uuid.New().String(),
		MovieId: uuid.New().String(),
	})
	requireCode(t, err, codes.OK)
}

// ── RemoveMovieFromWatchlist ──────────────────────────────────────────────────

func TestRemoveMovieFromWatchlist_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovieFromWatchlist(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestRemoveMovieFromWatchlist_InvalidUserID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovieFromWatchlist(context.Background(), &movieservicev1.RemoveMovieFromWatchlistRequest{
		UserId:  "bad",
		MovieId: uuid.New().String(),
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestRemoveMovieFromWatchlist_InvalidMovieID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovieFromWatchlist(context.Background(), &movieservicev1.RemoveMovieFromWatchlistRequest{
		UserId:  uuid.New().String(),
		MovieId: "bad",
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestRemoveMovieFromWatchlist_Success(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.RemoveMovieFromWatchlist(context.Background(), &movieservicev1.RemoveMovieFromWatchlistRequest{
		UserId:  uuid.New().String(),
		MovieId: uuid.New().String(),
	})
	requireCode(t, err, codes.OK)
}

// ── GetUserWatchlist ──────────────────────────────────────────────────────────

func TestGetUserWatchlist_NilRequest(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.GetUserWatchlist(context.Background(), nil)
	requireCode(t, err, codes.InvalidArgument)
}

func TestGetUserWatchlist_InvalidUserID(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{})
	_, err := h.GetUserWatchlist(context.Background(), &movieservicev1.GetUserWatchlistRequest{UserId: "bad"})
	requireCode(t, err, codes.InvalidArgument)
}

func TestGetUserWatchlist_RepoError(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{getErr: errors.New("db down")})
	_, err := h.GetUserWatchlist(context.Background(), &movieservicev1.GetUserWatchlistRequest{UserId: uuid.New().String()})
	requireCode(t, err, codes.Internal)
}

func TestGetUserWatchlist_Success(t *testing.T) {
	t.Parallel()
	movies := []domain.Movie{validDomainMovie(), validDomainMovie()}
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{movies: movies})
	resp, err := h.GetUserWatchlist(context.Background(), &movieservicev1.GetUserWatchlistRequest{UserId: uuid.New().String()})
	requireCode(t, err, codes.OK)
	if len(resp.GetMovies()) != 2 {
		t.Errorf("len(movies) = %d, want 2", len(resp.GetMovies()))
	}
}

func TestGetUserWatchlist_Empty(t *testing.T) {
	t.Parallel()
	h := newHandler(&mockMovieRepo{}, &mockWatchlistRepo{movies: nil})
	resp, err := h.GetUserWatchlist(context.Background(), &movieservicev1.GetUserWatchlistRequest{UserId: uuid.New().String()})
	requireCode(t, err, codes.OK)
	if len(resp.GetMovies()) != 0 {
		t.Errorf("expected 0 movies, got %d", len(resp.GetMovies()))
	}
}

// ── capturingMovieRepo ────────────────────────────────────────────────────────

type capturingMovieRepo struct {
	onUpsert func(domain.Movie) error
}

func (r *capturingMovieRepo) UpsertMovie(_ context.Context, m domain.Movie) error {
	if r.onUpsert != nil {
		return r.onUpsert(m)
	}
	return nil
}
func (r *capturingMovieRepo) ArchiveMovie(_ context.Context, _ uuid.UUID) error  { return nil }
func (r *capturingMovieRepo) RemoveMovie(_ context.Context, _ uuid.UUID) error   { return nil }
func (r *capturingMovieRepo) GetMovieByID(_ context.Context, _ uuid.UUID) (*domain.Movie, error) {
	return nil, nil
}
func (r *capturingMovieRepo) ListMovies(_ context.Context, _ ports.MovieFilter) ([]domain.Movie, error) {
	return nil, nil
}
