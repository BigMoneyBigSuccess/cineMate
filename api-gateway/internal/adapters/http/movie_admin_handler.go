package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/clients"
	"github.com/BigMoneyBigSuccess/cineMate/proto/movie-service/movieservicev1"
	"google.golang.org/grpc/status"
)

type MovieAdminHandler struct {
	movieClient *clients.MovieClient
}

func NewMovieAdminHandler(movieClient *clients.MovieClient) *MovieAdminHandler {
	return &MovieAdminHandler{movieClient: movieClient}
}

func (h *MovieAdminHandler) UpsertMovie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var movie movieservicev1.Movie
	if err := json.NewDecoder(r.Body).Decode(&movie); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if err := h.movieClient.UpsertMovie(r.Context(), &movie); err != nil {
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

func (h *MovieAdminHandler) ArchiveMovie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	movieID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/movies/")
	movieID = strings.TrimSuffix(movieID, "/archive")

	if err := h.movieClient.ArchiveMovie(r.Context(), movieID); err != nil {
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

func (h *MovieAdminHandler) RemoveMovie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	movieID := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/movies/")

	if err := h.movieClient.RemoveMovie(r.Context(), movieID); err != nil {
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
