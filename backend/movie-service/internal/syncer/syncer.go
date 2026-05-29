package syncer

import (
	"context"
	"log/slog"
	"time"

	"github.com/BigMoneyBigSuccess/cineMate/movie-service/internal/core/domain"
)

// movieUpserter is satisfied by usecase.MovieUseCase.
type movieUpserter interface {
	UpsertMovieInRepository(ctx context.Context, movie domain.Movie) error
}

// Syncer periodically fetches films from Kinopoisk and upserts them into the
// repository. It uses the Client's built-in rate limiter to respect the daily
// API budget; the loop itself is unbounded and runs until ctx is cancelled.
type Syncer struct {
	client       *Client
	movies       movieUpserter
	log          *slog.Logger
	fetchDesc    bool
	retryBackoff time.Duration
}

func New(client *Client, movies movieUpserter, log *slog.Logger, fetchDesc bool) *Syncer {
	if log == nil {
		log = slog.Default()
	}
	return &Syncer{
		client:       client,
		movies:       movies,
		log:          log.With("component", "syncer"),
		fetchDesc:    fetchDesc,
		retryBackoff: 5 * time.Minute,
	}
}

// Start launches the sync loop as a background goroutine.
func (s *Syncer) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *Syncer) run(ctx context.Context) {
	s.log.Info("syncer started")
	page := 1

	for {
		if ctx.Err() != nil {
			s.log.Info("syncer stopped")
			return
		}

		totalPages, err := s.syncPage(ctx, page)
		if err != nil {
			if ctx.Err() != nil {
				s.log.Info("syncer stopped")
				return
			}
			s.log.Error("syncer page error, retrying",
				"page", page,
				"error", err,
				"backoff", s.retryBackoff.String(),
			)
			select {
			case <-time.After(s.retryBackoff):
			case <-ctx.Done():
				s.log.Info("syncer stopped")
				return
			}
			continue
		}

		if page >= totalPages {
			s.log.Info("syncer cycle finished, restarting", "page", page, "total_pages", totalPages)
			page = 1
		} else {
			page++
		}
	}
}

// syncPage fetches one page of films and upserts each one. Returns totalPages
// so the caller knows when to wrap around.
func (s *Syncer) syncPage(ctx context.Context, page int) (int, error) {
	s.log.Debug("syncer fetching page", "page", page)

	filmsPage, err := s.client.GetFilmsPage(ctx, page)
	if err != nil {
		return 0, err
	}
	if filmsPage.TotalPages == 0 {
		return 1, nil
	}

	s.log.Info("syncer page fetched",
		"page", page,
		"films", len(filmsPage.Items),
		"total_pages", filmsPage.TotalPages,
	)

	for i, item := range filmsPage.Items {
		if ctx.Err() != nil {
			return filmsPage.TotalPages, ctx.Err()
		}
		s.log.Debug("syncer processing film",
			"index", i+1, "of", len(filmsPage.Items),
			"title", item.NameRu, "kinopoisk_id", item.KinopoiskID,
		)
		if err := s.syncFilm(ctx, item); err != nil {
			s.log.Warn("syncer skipped film",
				"kinopoisk_id", item.KinopoiskID,
				"title", item.NameRu,
				"error", err,
			)
		}
	}

	return filmsPage.TotalPages, nil
}

func (s *Syncer) syncFilm(ctx context.Context, item FilmItem) error {
	var detail *FilmDetail
	if s.fetchDesc {
		d, err := s.client.GetFilmDetail(ctx, item.KinopoiskID)
		if err != nil {
			return err
		}
		detail = d
	}

	staff, err := s.client.GetStaff(ctx, item.KinopoiskID)
	if err != nil {
		return err
	}

	movie := mapFilmToMovie(item, detail, staff)

	if err := movie.Validate(); err != nil {
		return err
	}

	if err := s.movies.UpsertMovieInRepository(ctx, movie); err != nil {
		return err
	}

	s.log.Info("syncer upserted movie", "kinopoisk_id", item.KinopoiskID, "title", movie.Title)
	return nil
}
