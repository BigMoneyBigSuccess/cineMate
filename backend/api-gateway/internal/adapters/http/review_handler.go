package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/clients"
	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"

	"google.golang.org/grpc/status"
)

type ReviewHandler struct {
	analyticsClient *clients.AnalyticsClient
}

func NewReviewHandler(analyticsClient *clients.AnalyticsClient) *ReviewHandler {
	return &ReviewHandler{analyticsClient: analyticsClient}
}

type upsertReviewRequest struct {
	FeedbackID *string `json:"feedback_id,omitempty"`
	Rating     int32   `json:"rating"`
	Title      *string `json:"title,omitempty"`
	Content    *string `json:"content,omitempty"`
}

func (h *ReviewHandler) UpsertReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		writeErrorResponse(w, "unauthenticated", "missing user")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/movies/")
	path = strings.TrimSuffix(path, "/reviews")
	movieID := path
	if movieID == "" {
		http.Error(w, "movie id is required", http.StatusBadRequest)
		return
	}

	var body upsertReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req := &analyticsv1.UpsertFeedbackRequest{
		FeedbackId: body.FeedbackID,
		UserId:     userID,
		MovieId:    movieID,
		Rating:     body.Rating,
		Title:      body.Title,
		Content:    body.Content,
	}

	feedbackID, err := h.analyticsClient.UpsertFeedback(r.Context(), req)
	if err != nil {
		writeStatusError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"feedback_id": feedbackID})
}

func (h *ReviewHandler) GetReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	feedbackID := strings.TrimPrefix(r.URL.Path, "/api/v1/reviews/")
	if feedbackID == "" {
		http.Error(w, "feedback id is required", http.StatusBadRequest)
		return
	}

	fb, err := h.analyticsClient.GetFeedback(r.Context(), feedbackID)
	if err != nil {
		writeStatusError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fb)
}

func (h *ReviewHandler) DeleteReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	feedbackID := strings.TrimPrefix(r.URL.Path, "/api/v1/reviews/")
	if feedbackID == "" {
		http.Error(w, "feedback id is required", http.StatusBadRequest)
		return
	}

	if err := h.analyticsClient.RemoveFeedback(r.Context(), feedbackID); err != nil {
		writeStatusError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ReviewHandler) ListUserReviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	userID = strings.TrimSuffix(userID, "/reviews")
	if userID == "" {
		http.Error(w, "user id is required", http.StatusBadRequest)
		return
	}

	fbs, err := h.analyticsClient.ListUserFeedback(r.Context(), userID)
	if err != nil {
		writeStatusError(w, err)
		return
	}

	if movieID := r.URL.Query().Get("movieId"); movieID != "" {
		filtered := fbs[:0]
		for _, fb := range fbs {
			if fb.GetMovieId() == movieID {
				filtered = append(filtered, fb)
			}
		}
		fbs = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"reviews": fbs, "total": len(fbs)})
}

func writeStatusError(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeGRPCErrorResponse(w, st.Code(), st.Message())
}
