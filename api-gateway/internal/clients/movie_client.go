package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/collections-service/api/proto/moviecollectionv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type MovieClient struct {
	catalogClient      moviecollectionv1.MovieCatalogServiceClient
	catalogAdminClient moviecollectionv1.MovieCatalogAdminServiceClient
	watchlistClient    moviecollectionv1.WatchlistServiceClient
	conn               *grpc.ClientConn
}

func NewMovieClient(ctx context.Context, host string, port int) (*MovieClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		return nil, fmt.Errorf("connect to collections service at %s: %w", addr, err)
	}

	return &MovieClient{
		catalogClient:      moviecollectionv1.NewMovieCatalogServiceClient(conn),
		catalogAdminClient: moviecollectionv1.NewMovieCatalogAdminServiceClient(conn),
		watchlistClient:    moviecollectionv1.NewWatchlistServiceClient(conn),
		conn:               conn,
	}, nil
}

func (mc *MovieClient) GetMovieByID(ctx context.Context, movieID string) (*moviecollectionv1.Movie, error) {
	resp, err := mc.catalogClient.GetMovieByID(ctx, &moviecollectionv1.GetMovieByIDRequest{
		MovieId: movieID,
	})

	if err != nil {
		return nil, err
	}

	return resp.Movie, nil
}

func (mc *MovieClient) ListMovies(ctx context.Context, req *moviecollectionv1.ListMoviesRequest) ([]*moviecollectionv1.Movie, error) {
	resp, err := mc.catalogClient.ListMovies(ctx, req)

	if err != nil {
		return nil, err
	}

	return resp.Movies, nil
}

func (mc *MovieClient) AddMovieToWatchlist(ctx context.Context, userID, movieID string) error {
	_, err := mc.watchlistClient.AddMovieToWatchlist(ctx, &moviecollectionv1.AddMovieToWatchlistRequest{
		UserId:  userID,
		MovieId: movieID,
	})

	return err
}

func (mc *MovieClient) RemoveMovieFromWatchlist(ctx context.Context, userID, movieID string) error {
	_, err := mc.watchlistClient.RemoveMovieFromWatchlist(ctx, &moviecollectionv1.RemoveMovieFromWatchlistRequest{
		UserId:  userID,
		MovieId: movieID,
	})

	return err
}

func (mc *MovieClient) GetWatchlist(ctx context.Context, userID string) ([]*moviecollectionv1.Movie, error) {
	resp, err := mc.watchlistClient.GetUserWatchlist(ctx, &moviecollectionv1.GetUserWatchlistRequest{
		UserId: userID,
	})

	if err != nil {
		return nil, err
	}

	return resp.Movies, nil
}

func (mc *MovieClient) Close() error {
	return mc.conn.Close()
}
