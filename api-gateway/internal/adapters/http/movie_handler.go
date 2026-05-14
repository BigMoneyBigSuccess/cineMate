package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/api-gateway/internal/clients"

	"github.com/BigMoneyBigSuccess/cineMate/collections-service/api/proto/moviecollectionv1"
	"google.golang.org/grpc/status"
)

type MovieHandler struct {
	movieClient *clients.MovieClient
}

func NewMovieHandler(movieClient *clients.MovieClient) *MovieHandler {
	return &MovieHandler{movieClient: movieClient}
}

func (h *MovieHandler) GetMovieByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/movies/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "movie id is required", http.StatusBadRequest)
		return
	}

	movie, err := h.movieClient.GetMovieByID(r.Context(), parts[0])
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeGRPCErrorResponse(w, st.Code(), st.Message())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(movie)
}

func (h *MovieHandler) ListMovies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	
	query := r.URL.Query()
	req := &moviecollectionv1.ListMoviesRequest{
		Query:           query.Get("q"),
		Limit:           int32(parseIntParam(query.Get("limit"), 20)),
		Offset:          int32(parseIntParam(query.Get("offset"), 0)),
		SortBy:          query.Get("sort_by"),
		SortOrder:       query.Get("sort_order"),
		IncludeArchived: parseIntParam(query.Get("include_archived"), 0) == 1,
	}

	
	if yearFrom := query.Get("release_year_from"); yearFrom != "" {
		year := int32(parseIntParam(yearFrom, 0))
		req.ReleaseYearFrom = &year
	}
	if yearTo := query.Get("release_year_to"); yearTo != "" {
		year := int32(parseIntParam(yearTo, 0))
		req.ReleaseYearTo = &year
	}

	
	if ratingFrom := query.Get("imdb_rating_from"); ratingFrom != "" {
		rating := float32(parseFloatParam(ratingFrom, 0))
		req.ImdbRatingFrom = &rating
	}
	if ratingTo := query.Get("imdb_rating_to"); ratingTo != "" {
		rating := float32(parseFloatParam(ratingTo, 10))
		req.ImdbRatingTo = &rating
	}

	movies, err := h.movieClient.ListMovies(r.Context(), req)
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeGRPCErrorResponse(w, st.Code(), st.Message())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"movies": movies,
		"total":  len(movies),
	})
}

func (h *MovieHandler) AddMovieToWatchlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)
	movieID := strings.TrimPrefix(r.URL.Path, "/api/v1/watchlist/")

	if err := h.movieClient.AddMovieToWatchlist(r.Context(), userID, movieID); err != nil {
		st, ok := status.FromError(err)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeGRPCErrorResponse(w, st.Code(), st.Message())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *MovieHandler) RemoveMovieFromWatchlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)
	movieID := strings.TrimPrefix(r.URL.Path, "/api/v1/watchlist/")

	if err := h.movieClient.RemoveMovieFromWatchlist(r.Context(), userID, movieID); err != nil {
		st, ok := status.FromError(err)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeGRPCErrorResponse(w, st.Code(), st.Message())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *MovieHandler) GetWatchlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(string)

	movies, err := h.movieClient.GetWatchlist(r.Context(), userID)
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		writeGRPCErrorResponse(w, st.Code(), st.Message())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"movies": movies,
		"total":  len(movies),
	})
}

func parseIntParam(value string, defaultValue int) int {
	if value == "" {
		return defaultValue
	}
	if intVal, err := strconv.Atoi(value); err == nil {
		return intVal
	}
	return defaultValue
}

func parseFloatParam(value string, defaultValue float64) float64 {
	if value == "" {
		return defaultValue
	}
	if floatVal, err := strconv.ParseFloat(value, 32); err == nil {
		return floatVal
	}
	return defaultValue
}
