package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/clients"
	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"
)

type RecommendationsHandler struct {
	analyticsClient *clients.AnalyticsClient
}

func NewRecommendationsHandler(analyticsClient *clients.AnalyticsClient) *RecommendationsHandler {
	return &RecommendationsHandler{analyticsClient: analyticsClient}
}

func (h *RecommendationsHandler) GenerateForCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		writeErrorResponse(w, "unauthenticated", "missing user")
		return
	}

	q := r.URL.Query()
	recs, err := h.analyticsClient.GenerateRecommendations(r.Context(), &analyticsv1.GenerateRecommendationsRequest{
		UserId:   userID,
		Strategy: q.Get("strategy"),
		Limit:    int32(parseIntParam(q.Get("limit"), 0)),
	})
	if err != nil {
		writeStatusError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"recommendations": recs, "total": len(recs)})
}

func (h *RecommendationsHandler) HistoryForCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		writeErrorResponse(w, "unauthenticated", "missing user")
		return
	}

	q := r.URL.Query()
	recs, err := h.analyticsClient.GetRecommendationHistory(r.Context(), &analyticsv1.GetRecommendationHistoryRequest{
		UserId:   userID,
		Strategy: q.Get("strategy"),
		Limit:    int32(parseIntParam(q.Get("limit"), 0)),
	})
	if err != nil {
		writeStatusError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"recommendations": recs, "total": len(recs)})
}

func (h *RecommendationsHandler) ResetHistoryForCurrentUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := r.Context().Value("user_id").(string)
	if !ok || userID == "" {
		writeErrorResponse(w, "unauthenticated", "missing user")
		return
	}

	if err := h.analyticsClient.ResetRecommendationHistory(r.Context(), userID); err != nil {
		writeStatusError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RecommendationsHandler) MarkInteraction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/recommendations/")
	rest = strings.TrimSuffix(rest, "/interactions")
	recommendationID := rest
	if recommendationID == "" {
		http.Error(w, "recommendation id is required", http.StatusBadRequest)
		return
	}

	var body struct {
		Interaction string `json:"interaction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.analyticsClient.MarkInteraction(r.Context(), recommendationID, body.Interaction); err != nil {
		writeStatusError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
