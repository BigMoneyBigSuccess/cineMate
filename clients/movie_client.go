package clients

import (
	"context"
	"fmt"

	"github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type MovieClient struct {
	catalogClient      movieservicev1.MovieServiceClient
	catalogAdminClient movieservicev1.MovieAdminServiceClient
	watchlistClient    movieservicev1.WatchlistServiceClient
	conn               *grpc.ClientConn
}

func NewMovieClient(host string, port int) (*MovieClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to movies service at %s: %w", addr, err)
	}
	return &MovieClient{
		catalogClient:      movieservicev1.NewMovieServiceClient(conn),
		catalogAdminClient: movieservicev1.NewMovieAdminServiceClient(conn),
		watchlistClient:    movieservicev1.NewWatchlistServiceClient(conn),
		conn:               conn,
	}, nil
}

func (mc *MovieClient) GetMovieByID(ctx context.Context, movieID string) (*movieservicev1.Movie, error) {
	resp, err := mc.catalogClient.GetMovieByID(ctx, &movieservicev1.GetMovieByIDRequest{MovieId: movieID})
	if err != nil {
		return nil, err
	}
	return resp.Movie, nil
}

func (mc *MovieClient) ListMovies(ctx context.Context, req *movieservicev1.ListMoviesRequest) ([]*movieservicev1.Movie, error) {
	resp, err := mc.catalogClient.ListMovies(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Movies, nil
}

func (mc *MovieClient) AddMovieToWatchlist(ctx context.Context, userID, movieID string) error {
	_, err := mc.watchlistClient.AddMovieToWatchlist(ctx, &movieservicev1.AddMovieToWatchlistRequest{
		UserId:  userID,
		MovieId: movieID,
	})
	return err
}

func (mc *MovieClient) RemoveMovieFromWatchlist(ctx context.Context, userID, movieID string) error {
	_, err := mc.watchlistClient.RemoveMovieFromWatchlist(ctx, &movieservicev1.RemoveMovieFromWatchlistRequest{
		UserId:  userID,
		MovieId: movieID,
	})
	return err
}

func (mc *MovieClient) GetWatchlist(ctx context.Context, userID string) ([]*movieservicev1.Movie, error) {
	resp, err := mc.watchlistClient.GetUserWatchlist(ctx, &movieservicev1.GetUserWatchlistRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return resp.Movies, nil
}

func (mc *MovieClient) Close() error {
	return mc.conn.Close()
}
