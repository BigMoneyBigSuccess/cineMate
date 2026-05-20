package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"movie_service/internal/core/domain"
	"movie_service/internal/core/ports"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	defaultKeyPrefix = "movie_collection"
	defaultMovieTTL  = 30 * time.Minute
	defaultListTTL   = 2 * time.Minute
)

var _ ports.MovieRepository = (*MovieCache)(nil)

type MovieCache struct {
	// field "next" is next layer in the repository chain,
	// used to fetch data on cache miss and to perform write operations
	next     ports.MovieRepository
	client   redis.Cmdable
	movieTTL time.Duration
	listTTL  time.Duration
	prefix   string
}

func NewMovieCache(next ports.MovieRepository, client redis.Cmdable, movieTTL, listTTL time.Duration) *MovieCache {
	if movieTTL <= 0 {
		movieTTL = defaultMovieTTL
	}
	if listTTL <= 0 {
		listTTL = defaultListTTL
	}

	return &MovieCache{
		next:     next,
		client:   client,
		movieTTL: movieTTL,
		listTTL:  listTTL,
		prefix:   defaultKeyPrefix,
	}
}

func (c *MovieCache) UpsertMovie(ctx context.Context, movie domain.Movie) error {
	if err := c.next.UpsertMovie(ctx, movie); err != nil {
		return err
	}

	c.invalidateReadCaches(ctx)
	return nil
}

func (c *MovieCache) ArchiveMovie(ctx context.Context, id uuid.UUID) error {
	if err := c.next.ArchiveMovie(ctx, id); err != nil {
		return err
	}

	c.invalidateReadCaches(ctx)
	return nil
}

func (c *MovieCache) RemoveMovie(ctx context.Context, id uuid.UUID) error {
	if err := c.next.RemoveMovie(ctx, id); err != nil {
		return err
	}

	c.invalidateReadCaches(ctx)
	return nil
}

func (c *MovieCache) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.Movie, error) {
	if c.client == nil {
		return c.next.GetMovieByID(ctx, id)
	}

	version, ok := c.readVersion(ctx, c.movieVersionKey())
	if ok {
		if movie, found := c.getCachedMovie(ctx, c.movieKey(version, id)); found {
			return movie, nil
		}
	}

	movie, err := c.next.GetMovieByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if ok {
		c.setCachedMovie(ctx, c.movieKey(version, id), movie)
	}

	return movie, nil
}

func (c *MovieCache) ListMovies(ctx context.Context, filter ports.MovieFilter) ([]domain.Movie, error) {
	if c.client == nil {
		return c.next.ListMovies(ctx, filter)
	}

	version, ok := c.readVersion(ctx, c.listVersionKey())
	if ok {
		key, err := c.listKey(version, filter)
		if err == nil {
			if movies, found := c.getCachedMovieList(ctx, key); found {
				return movies, nil
			}
		}
	}

	movies, err := c.next.ListMovies(ctx, filter)
	if err != nil {
		return nil, err
	}

	if ok {
		if key, keyErr := c.listKey(version, filter); keyErr == nil {
			c.setCachedMovieList(ctx, key, movies)
		}
	}

	return movies, nil
}

func (c *MovieCache) invalidateReadCaches(ctx context.Context) {
	if c.client == nil {
		return
	}

	_ = c.client.Incr(ctx, c.movieVersionKey()).Err()
	_ = c.client.Incr(ctx, c.listVersionKey()).Err()
}

func (c *MovieCache) readVersion(ctx context.Context, key string) (int64, bool) {
	version, err := c.client.Get(ctx, key).Int64()
	switch {
	case err == nil:
		return version, true
	case errors.Is(err, redis.Nil):
		return 0, true
	default:
		return 0, false
	}
}

func (c *MovieCache) getCachedMovie(ctx context.Context, key string) (*domain.Movie, bool) {
	payload, err := c.client.Get(ctx, key).Bytes()
	switch {
	case err == nil:
	case errors.Is(err, redis.Nil):
		return nil, false
	default:
		return nil, false
	}

	var movie domain.Movie
	if err := json.Unmarshal(payload, &movie); err != nil {
		_ = c.client.Del(ctx, key).Err()
		return nil, false
	}

	return &movie, true
}

func (c *MovieCache) setCachedMovie(ctx context.Context, key string, movie *domain.Movie) {
	if movie == nil {
		return
	}

	payload, err := json.Marshal(movie)
	if err != nil {
		return
	}

	_ = c.client.Set(ctx, key, payload, c.movieTTL).Err()
}

func (c *MovieCache) getCachedMovieList(ctx context.Context, key string) ([]domain.Movie, bool) {
	payload, err := c.client.Get(ctx, key).Bytes()
	switch {
	case err == nil:
	case errors.Is(err, redis.Nil):
		return nil, false
	default:
		return nil, false
	}

	var movies []domain.Movie
	if err := json.Unmarshal(payload, &movies); err != nil {
		_ = c.client.Del(ctx, key).Err()
		return nil, false
	}

	return movies, true
}

func (c *MovieCache) setCachedMovieList(ctx context.Context, key string, movies []domain.Movie) {
	payload, err := json.Marshal(movies)
	if err != nil {
		return
	}

	_ = c.client.Set(ctx, key, payload, c.listTTL).Err()
}

func (c *MovieCache) movieVersionKey() string {
	return fmt.Sprintf("%s:movies:version", c.prefix)
}

func (c *MovieCache) listVersionKey() string {
	return fmt.Sprintf("%s:movies:list-version", c.prefix)
}

func (c *MovieCache) movieKey(version int64, id uuid.UUID) string {
	return fmt.Sprintf("%s:movies:v%d:id:%s", c.prefix, version, id.String())
}

func (c *MovieCache) listKey(version int64, filter ports.MovieFilter) (string, error) {
	payload, err := json.Marshal(filter)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%s:movies:list:v%d:%s", c.prefix, version, hex.EncodeToString(sum[:])), nil
}
