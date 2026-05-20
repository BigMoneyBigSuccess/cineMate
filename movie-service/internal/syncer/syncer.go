package syncer

import (
	"context"
	"log"
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
	fetchDesc    bool
	retryBackoff time.Duration
}

func New(client *Client, movies movieUpserter, fetchDesc bool) *Syncer {
	return &Syncer{
		client:       client,
		movies:       movies,
		fetchDesc:    fetchDesc,
		retryBackoff: 5 * time.Minute,
	}
}

// Start launches the sync loop as a background goroutine.
func (s *Syncer) Start(ctx context.Context) {
	go s.run(ctx)
}

func (s *Syncer) run(ctx context.Context) {
	log.Print("syncer: started")
	page := 1

	for {
		if ctx.Err() != nil {
			log.Print("syncer: stopped")
			return
		}

		totalPages, err := s.syncPage(ctx, page)
		if err != nil {
			if ctx.Err() != nil {
				log.Print("syncer: stopped")
				return
			}
			log.Printf("syncer: page %d error: %v — retrying in %s", page, err, s.retryBackoff)
			select {
			case <-time.After(s.retryBackoff):
			case <-ctx.Done():
				log.Print("syncer: stopped")
				return
			}
			continue
		}

		if page >= totalPages {
			log.Printf("syncer: finished cycle at page %d/%d, restarting", page, totalPages)
			page = 1
		} else {
			page++
		}
	}
}

// syncPage fetches one page of films and upserts each one. Returns totalPages
// so the caller knows when to wrap around.
func (s *Syncer) syncPage(ctx context.Context, page int) (int, error) {
	log.Printf("syncer: fetching page %d", page)

	filmsPage, err := s.client.GetFilmsPage(ctx, page)
	if err != nil {
		return 0, err
	}
	if filmsPage.TotalPages == 0 {
		return 1, nil
	}

	log.Printf("syncer: page %d — %d films, %d total pages", page, len(filmsPage.Items), filmsPage.TotalPages)

	for i, item := range filmsPage.Items {
		if ctx.Err() != nil {
			return filmsPage.TotalPages, ctx.Err()
		}
		log.Printf("syncer: processing film %d/%d — %s (id=%d)", i+1, len(filmsPage.Items), item.NameRu, item.KinopoiskID)
		if err := s.syncFilm(ctx, item); err != nil {
			log.Printf("syncer: skip film %d (%s): %v", item.KinopoiskID, item.NameRu, err)
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

	log.Printf("syncer: upserted %d — %s", item.KinopoiskID, movie.Title)
	return nil
}
