package http

import (
	"context"

	"movie_collection/api/proto/moviecollectionv1"
	"movie_collection/internal/core/usecase"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type MovieHandler struct {
	moviecollectionv1.UnimplementedMovieCatalogServiceServer
	moviecollectionv1.UnimplementedMovieCatalogAdminServiceServer
	moviecollectionv1.UnimplementedWatchlistServiceServer

	movies    *usecase.MovieUseCase
	watchlist *usecase.WatchlistUseCase
}

func NewMovieHandler(movies *usecase.MovieUseCase, watchlist *usecase.WatchlistUseCase) *MovieHandler {
	return &MovieHandler{
		movies:    movies,
		watchlist: watchlist,
	}
}

func (h *MovieHandler) GetMovieByID(ctx context.Context, req *moviecollectionv1.GetMovieByIDRequest) (*moviecollectionv1.GetMovieByIDResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	movieID, err := parseUUID(req.GetMovieId(), "movie_id")
	if err != nil {
		return nil, err
	}

	movie, err := h.movies.GetMovieByID(ctx, movieID)
	if err != nil {
		return nil, mapError(err)
	}

	return &moviecollectionv1.GetMovieByIDResponse{
		Movie: movieToProto(*movie),
	}, nil
}

func (h *MovieHandler) ListMovies(ctx context.Context, req *moviecollectionv1.ListMoviesRequest) (*moviecollectionv1.ListMoviesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.GetLimit() < 0 {
		return nil, status.Error(codes.InvalidArgument, "limit must be non-negative")
	}
	if req.GetOffset() < 0 {
		return nil, status.Error(codes.InvalidArgument, "offset must be non-negative")
	}

	filter, err := listRequestToFilter(req)
	if err != nil {
		return nil, err
	}

	movies, err := h.movies.ListMovies(ctx, filter)
	if err != nil {
		return nil, mapError(err)
	}

	response := &moviecollectionv1.ListMoviesResponse{
		Movies: make([]*moviecollectionv1.Movie, 0, len(movies)),
	}
	for _, movie := range movies {
		response.Movies = append(response.Movies, movieToProto(movie))
	}

	return response, nil
}

func (h *MovieHandler) UpsertMovie(ctx context.Context, req *moviecollectionv1.UpsertMovieRequest) (*emptypb.Empty, error) {
	if req == nil || req.GetMovie() == nil {
		return nil, status.Error(codes.InvalidArgument, "movie is required")
	}

	movie, err := protoToMovie(req.GetMovie())
	if err != nil {
		return nil, err
	}

	if err := h.movies.UpsertMovieInRepository(ctx, movie); err != nil {
		return nil, mapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *MovieHandler) ArchiveMovie(ctx context.Context, req *moviecollectionv1.ArchiveMovieRequest) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	movieID, err := parseUUID(req.GetMovieId(), "movie_id")
	if err != nil {
		return nil, err
	}

	if err := h.movies.ArchiveMovieInRepository(ctx, movieID); err != nil {
		return nil, mapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *MovieHandler) RemoveMovie(ctx context.Context, req *moviecollectionv1.RemoveMovieRequest) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	movieID, err := parseUUID(req.GetMovieId(), "movie_id")
	if err != nil {
		return nil, err
	}

	if err := h.movies.RemoveMovieFromRepository(ctx, movieID); err != nil {
		return nil, mapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *MovieHandler) AddMovieToWatchlist(ctx context.Context, req *moviecollectionv1.AddMovieToWatchlistRequest) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	movieID, err := parseUUID(req.GetMovieId(), "movie_id")
	if err != nil {
		return nil, err
	}

	if err := h.watchlist.AddMovieToWatchlist(ctx, userID, movieID); err != nil {
		return nil, mapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *MovieHandler) RemoveMovieFromWatchlist(ctx context.Context, req *moviecollectionv1.RemoveMovieFromWatchlistRequest) (*emptypb.Empty, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	movieID, err := parseUUID(req.GetMovieId(), "movie_id")
	if err != nil {
		return nil, err
	}

	if err := h.watchlist.RemoveMovieFromWatchlist(ctx, userID, movieID); err != nil {
		return nil, mapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (h *MovieHandler) GetUserWatchlist(ctx context.Context, req *moviecollectionv1.GetUserWatchlistRequest) (*moviecollectionv1.GetUserWatchlistResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	userID, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}

	movies, err := h.watchlist.GetUserWatchlist(ctx, userID)
	if err != nil {
		return nil, mapError(err)
	}

	response := &moviecollectionv1.GetUserWatchlistResponse{
		Movies: make([]*moviecollectionv1.Movie, 0, len(movies)),
	}
	for _, movie := range movies {
		response.Movies = append(response.Movies, movieToProto(movie))
	}

	return response, nil
}
