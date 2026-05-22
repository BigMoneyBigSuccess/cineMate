package movieservice

import (
	"context"
	"fmt"
	"time"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/BigMoneyBigSuccess/cineMate/clients"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MovieServiceClient struct {
	client  *clients.MovieClient
	timeout time.Duration
}

func NewMovieServiceClient(client *clients.MovieClient, timeout time.Duration) *MovieServiceClient {
	return &MovieServiceClient{client: client, timeout: timeout}
}

func (c *MovieServiceClient) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	m, err := c.client.GetMovieByID(ctx, id.String())
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("movie %s: %w", id, domain.ErrInvalidMovieReference)
		}
		return nil, fmt.Errorf("GetMovieByID: %w", err)
	}
	return protoToSnapshot(m)
}

func (c *MovieServiceClient) ListMovies(ctx context.Context, filter ports.MovieFilter) ([]domain.MovieSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	movies, err := c.client.ListMovies(ctx, filterToProto(filter))
	if err != nil {
		return nil, fmt.Errorf("ListMovies: %w", err)
	}

	snapshots := make([]domain.MovieSnapshot, 0, len(movies))
	for _, m := range movies {
		snap, err := protoToSnapshot(m)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, *snap)
	}
	return snapshots, nil
}

var _ ports.MovieRepository = (*MovieServiceClient)(nil)
