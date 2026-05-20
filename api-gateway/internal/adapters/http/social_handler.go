package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/clients"

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
		Username string `json:"username"`
		Bio      string `json:"bio"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.socialClient.UpdateProfile(r.Context(), token, body.Username, body.Bio); err != nil {
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
