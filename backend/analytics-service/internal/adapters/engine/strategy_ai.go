package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"
	"github.com/google/uuid"
)

const (
	minFeedbackForPrompt = 15
	maxFeedbackForPrompt = 20
	minLikedRating       = 6
)

// recommendByAI calls the AI model with a prompt built from the user's top-rated
// movies and returns a single MovieRecommendation whose AIResponse field holds
// the raw model text. No catalog lookup is performed — the AI answer is the value.
func (e *Engine) recommendByAI(ctx context.Context, filter ports.RecommendationFilter) ([]domain.MovieRecommendation, error) {
	if e.aiClient == nil {
		return nil, fmt.Errorf("AI strategy is not configured: no AI client provided")
	}

	entries := selectFeedbackForPrompt(filter.Feedback)
	if len(entries) == 0 {
		return nil, fmt.Errorf("AI strategy requires at least one rated movie in history")
	}

	resolved := e.resolveFeedbackTitles(ctx, entries)
	if len(resolved) == 0 {
		return nil, fmt.Errorf("could not resolve any movie titles for AI prompt")
	}

	prompt := buildPrompt(resolved, filter.Limit)

	response, err := e.aiClient.Complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI completion failed: %w", err)
	}

	aiResp := response
	return []domain.MovieRecommendation{{
		RecommendationID: uuid.New(),
		SessionID:        uuid.New(),
		UserID:           filter.Profile.UserID,
		MovieID:          nil,
		AIResponse:       &aiResp,
		Rank:             1,
		Strategy:         domain.StrategyAIModelBased,
		GeneratedAt:      time.Now(),
		Interaction:      domain.InteractionTypeDismiss,
	}}, nil
}

func selectFeedbackForPrompt(feedback []domain.MovieFeedback) []domain.MovieFeedback {
	liked := make([]domain.MovieFeedback, 0, len(feedback))
	for _, fb := range feedback {
		if fb.Rating >= minLikedRating {
			liked = append(liked, fb)
		}
	}
	if len(liked) < minFeedbackForPrompt && len(feedback) > len(liked) {
		liked = feedback
	}

	sort.Slice(liked, func(i, j int) bool {
		return liked[i].Rating > liked[j].Rating
	})

	if len(liked) > maxFeedbackForPrompt {
		liked = liked[:maxFeedbackForPrompt]
	}
	return liked
}

type resolvedEntry struct {
	title  string
	rating int32
	review string
}

func (e *Engine) resolveFeedbackTitles(ctx context.Context, entries []domain.MovieFeedback) []resolvedEntry {
	result := make([]resolvedEntry, 0, len(entries))
	for _, fb := range entries {
		snap, err := e.movies.GetMovieByID(ctx, fb.MovieID)
		if err != nil || snap == nil {
			continue
		}
		result = append(result, resolvedEntry{
			title:  snap.Title,
			rating: fb.Rating,
			review: buildReviewText(fb),
		})
	}
	return result
}

func buildReviewText(fb domain.MovieFeedback) string {
	var parts []string
	if fb.Title != nil && *fb.Title != "" {
		parts = append(parts, fmt.Sprintf("title: %q", *fb.Title))
	}
	if fb.Content != nil && *fb.Content != "" {
		parts = append(parts, fmt.Sprintf("review: %q", *fb.Content))
	}
	return strings.Join(parts, ", ")
}

func buildPrompt(entries []resolvedEntry, wantCount int) string {
	var sb strings.Builder

	sb.WriteString("I am a movie enthusiast. Here are movies I have watched along with my ratings and personal reviews:\n\n")

	for i, e := range entries {
		if e.review != "" {
			fmt.Fprintf(&sb, "%d. \"%s\" — Rating: %d/10 (%s)\n", i+1, e.title, e.rating, e.review)
		} else {
			fmt.Fprintf(&sb, "%d. \"%s\" — Rating: %d/10\n", i+1, e.title, e.rating)
		}
	}

	fmt.Fprintf(&sb,
		"\nBased on my taste shown above, recommend exactly %d movies I would enjoy but haven't seen yet. "+
			"For each movie include the title, year, and a sentence explaining why I would like it based on my reviews.\n"+

			"Do not include any movies I have already rated above. Format the response as a numbered list.\n"+

			"Importantly, only recommend movies that actually exist and can be found on IMDb. Do not make up any movie titles or details. "+
			"If you are unsure, it's better to recommend fewer than %d movies rather than fabricating information.\n"+

			"Do not format your response with markdown or use any special characters — just numbered list of answers in plain text without any additional formatting.\n"+

			"Do not add to your answers any disclaimers, hedging language, or self-reflection about the limitations of your recommendations. "+
			"Just give me the recommendations in a straightforward manner without any additional commentary.\n",
		wantCount,
		wantCount,
	)

	return sb.String()
}
