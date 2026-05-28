package clients

import (
	"context"
	"fmt"

	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AnalyticsClient struct {
	feedbackClient        analyticsv1.FeedbackServiceClient
	recommendationsClient analyticsv1.RecommendationServiceClient
	conn                  *grpc.ClientConn
}

func NewAnalyticsClient(host string, port int) (*AnalyticsClient, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to analytics service at %s: %w", addr, err)
	}
	return &AnalyticsClient{
		feedbackClient:        analyticsv1.NewFeedbackServiceClient(conn),
		recommendationsClient: analyticsv1.NewRecommendationServiceClient(conn),
		conn:                  conn,
	}, nil
}

func (c *AnalyticsClient) Close() error { return c.conn.Close() }

// ─── Feedback (a.k.a. user reviews) ───────────────────────────────────────────

func (c *AnalyticsClient) UpsertFeedback(ctx context.Context, req *analyticsv1.UpsertFeedbackRequest) (string, error) {
	resp, err := c.feedbackClient.UpsertFeedback(ctx, req)
	if err != nil {
		return "", err
	}
	return resp.FeedbackId, nil
}

func (c *AnalyticsClient) RemoveFeedback(ctx context.Context, feedbackID string) error {
	_, err := c.feedbackClient.RemoveFeedback(ctx, &analyticsv1.RemoveFeedbackRequest{FeedbackId: feedbackID})
	return err
}

func (c *AnalyticsClient) GetFeedback(ctx context.Context, feedbackID string) (*analyticsv1.Feedback, error) {
	resp, err := c.feedbackClient.GetFeedback(ctx, &analyticsv1.GetFeedbackRequest{FeedbackId: feedbackID})
	if err != nil {
		return nil, err
	}
	return resp.Feedback, nil
}

func (c *AnalyticsClient) ListUserFeedback(ctx context.Context, userID string) ([]*analyticsv1.Feedback, error) {
	resp, err := c.feedbackClient.ListUserFeedback(ctx, &analyticsv1.ListUserFeedbackRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	return resp.Feedback, nil
}

// ─── Recommendations ──────────────────────────────────────────────────────────

func (c *AnalyticsClient) GenerateRecommendations(ctx context.Context, req *analyticsv1.GenerateRecommendationsRequest) ([]*analyticsv1.Recommendation, error) {
	resp, err := c.recommendationsClient.GenerateRecommendations(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Recommendations, nil
}

func (c *AnalyticsClient) GetRecommendationHistory(ctx context.Context, req *analyticsv1.GetRecommendationHistoryRequest) ([]*analyticsv1.Recommendation, error) {
	resp, err := c.recommendationsClient.GetRecommendationHistory(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Recommendations, nil
}

func (c *AnalyticsClient) MarkInteraction(ctx context.Context, recommendationID, interaction string) error {
	_, err := c.recommendationsClient.MarkInteraction(ctx, &analyticsv1.MarkInteractionRequest{
		RecommendationId: recommendationID,
		Interaction:      interaction,
	})
	return err
}

func (c *AnalyticsClient) ResetRecommendationHistory(ctx context.Context, userID string) error {
	_, err := c.recommendationsClient.ResetRecommendationHistory(ctx, &analyticsv1.ResetRecommendationHistoryRequest{UserId: userID})
	return err
}
