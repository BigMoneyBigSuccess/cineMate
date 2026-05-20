package moviecollection

import (
	"context"
	"fmt"
	"time"

	"analytics/api/proto/moviecollectionv1"
	"analytics/internal/config"
	"analytics/internal/core/domain"
	"analytics/internal/core/ports"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// MovieCollectionClient implements ports.MovieRepository by delegating to the
// movie-collection service over gRPC.
type MovieCollectionClient struct {
	client  moviecollectionv1.MovieCatalogServiceClient
	timeout time.Duration
}

// NewConn creates a gRPC client connection to the movie-collection service.
// The caller is responsible for closing it.
func NewConn(cfg config.MovieCollectionConfig) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(cfg.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial movie-collection service at %s: %w", cfg.Addr, err)
	}
	return conn, nil
}

func New(conn *grpc.ClientConn, timeout time.Duration) *MovieCollectionClient {
	return &MovieCollectionClient{
		client:  moviecollectionv1.NewMovieCatalogServiceClient(conn),
		timeout: timeout,
	}
}

func (c *MovieCollectionClient) GetMovieByID(ctx context.Context, id uuid.UUID) (*domain.MovieSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.GetMovieByID(ctx, &moviecollectionv1.GetMovieByIDRequest{
		MovieId: id.String(),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("movie %s: %w", id, domain.ErrInvalidMovieReference)
		}
		return nil, fmt.Errorf("GetMovieByID: %w", err)
	}

	return protoToSnapshot(resp.Movie)
}

func (c *MovieCollectionClient) ListMovies(ctx context.Context, filter ports.MovieFilter) ([]domain.MovieSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.client.ListMovies(ctx, filterToProto(filter))
	if err != nil {
		return nil, fmt.Errorf("ListMovies: %w", err)
	}

	snapshots := make([]domain.MovieSnapshot, 0, len(resp.Movies))
	for _, m := range resp.Movies {
		snap, err := protoToSnapshot(m)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, *snap)
	}
	return snapshots, nil
}

// compile-time interface check
var _ ports.MovieRepository = (*MovieCollectionClient)(nil)
