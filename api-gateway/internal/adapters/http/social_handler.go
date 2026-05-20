package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/api-gateway/internal/clients"

	"google.golang.org/grpc/status"
)

type SocialHandler struct {
	socialClient *clients.SocialClient
}

func NewSocialHandler(socialClient *clients.SocialClient) *SocialHandler {
	return &SocialHandler{socialClient: socialClient}
}

func (h *SocialHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID = strings.TrimSuffix(userID, "/profile")

	profile, err := h.socialClient.GetProfile(r.Context(), userID)
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
	json.NewEncoder(w).Encode(profile)
}

func (h *SocialHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bearerToken(r)
	if token == "" {
		writeErrorResponse(w, "unauthenticated", "authorization header is required")
		return
	}

	var body struct {
		Username  string `json:"username"`
		AvatarURL string `json:"avatar_url"`
		Bio       string `json:"bio"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.socialClient.UpdateProfile(r.Context(), token, body.Username, body.AvatarURL, body.Bio); err != nil {
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

func (h *SocialHandler) FollowUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bearerToken(r)
	if token == "" {
		writeErrorResponse(w, "unauthenticated", "authorization header is required")
		return
	}

	followedID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	followedID = strings.TrimSuffix(followedID, "/follow")

	if err := h.socialClient.FollowUser(r.Context(), token, followedID); err != nil {
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

func (h *SocialHandler) UnfollowUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bearerToken(r)
	if token == "" {
		writeErrorResponse(w, "unauthenticated", "authorization header is required")
		return
	}

	followedID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	followedID = strings.TrimSuffix(followedID, "/follow")

	if err := h.socialClient.UnfollowUser(r.Context(), token, followedID); err != nil {
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

func (h *SocialHandler) GetFollowers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID = strings.TrimSuffix(userID, "/followers")
	limit, offset := parsePagination(r)

	resp, err := h.socialClient.GetFollowers(r.Context(), userID, limit, offset)
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
	json.NewEncoder(w).Encode(map[string]any{"follower_ids": resp.FollowerIds, "total": resp.Total})
}

func (h *SocialHandler) GetFollowing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID = strings.TrimSuffix(userID, "/following")
	limit, offset := parsePagination(r)

	resp, err := h.socialClient.GetFollowing(r.Context(), userID, limit, offset)
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
	json.NewEncoder(w).Encode(map[string]any{"following_ids": resp.FollowingIds, "total": resp.Total})
}

func (h *SocialHandler) GetWatchlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID = strings.TrimSuffix(userID, "/watchlist")
	limit, offset := parsePagination(r)

	resp, err := h.socialClient.GetWatchlist(r.Context(), userID, limit, offset)
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
	json.NewEncoder(w).Encode(map[string]any{"movie_ids": resp.MovieIds, "total": resp.Total})
}

func (h *SocialHandler) WatchlistEntry(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeErrorResponse(w, "unauthenticated", "authorization header is required")
		return
	}

	movieID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/me/watchlist/")

	var err error
	switch r.Method {
	case http.MethodPost:
		err = h.socialClient.AddToWatchlist(r.Context(), token, movieID)
	case http.MethodDelete:
		err = h.socialClient.RemoveFromWatchlist(r.Context(), token, movieID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
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

func (h *SocialHandler) GetWatched(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID = strings.TrimSuffix(userID, "/watched")
	limit, offset := parsePagination(r)

	resp, err := h.socialClient.GetWatched(r.Context(), userID, limit, offset)
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
	json.NewEncoder(w).Encode(map[string]any{"movie_ids": resp.MovieIds, "total": resp.Total})
}

func (h *SocialHandler) WatchedEntry(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeErrorResponse(w, "unauthenticated", "authorization header is required")
		return
	}

	movieID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/me/watched/")

	var err error
	switch r.Method {
	case http.MethodPost:
		err = h.socialClient.MarkWatched(r.Context(), token, movieID)
	case http.MethodDelete:
		err = h.socialClient.UnmarkWatched(r.Context(), token, movieID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
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

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return h[7:]
	}
	return ""
}

func parsePagination(r *http.Request) (limit, offset int32) {
	limit = int32(parseIntParam(r.URL.Query().Get("limit"), 20))
	offset = int32(parseIntParam(r.URL.Query().Get("offset"), 0))
	return
}
