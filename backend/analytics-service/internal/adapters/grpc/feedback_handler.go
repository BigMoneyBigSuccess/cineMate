package grpc

import (
	"context"

	analyticsv1 "github.com/BigMoneyBigSuccess/cineMate/proto/analytics-service/analyticsservicev1"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/usecase"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type FeedbackHandler struct {
	analyticsv1.UnimplementedFeedbackServiceServer
	feedbackUC *usecase.FeedbackUseCase
	profileUC  *usecase.UserProfileUseCase
}

func NewFeedbackHandler(feedbackUC *usecase.FeedbackUseCase, profileUC *usecase.UserProfileUseCase) *FeedbackHandler {
	return &FeedbackHandler{feedbackUC: feedbackUC, profileUC: profileUC}
}

func (h *FeedbackHandler) UpsertFeedback(ctx context.Context, req *analyticsv1.UpsertFeedbackRequest) (*analyticsv1.UpsertFeedbackResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}
	movieID, err := uuid.Parse(req.GetMovieId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid movie_id: %v", err)
	}

	feedbackID := uuid.New()
	if req.FeedbackId != nil {
		feedbackID, err = uuid.Parse(req.GetFeedbackId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid feedback_id: %v", err)
		}
	}

	fb := domain.MovieFeedback{
		FeedbackID: feedbackID,
		UserID:     userID,
		MovieID:    movieID,
		Rating:     req.GetRating(),
		Title:      req.Title,
		Content:    req.Content,
	}

	if err := h.feedbackUC.UpsertFeedback(ctx, fb); err != nil {
		return nil, domainErr(err)
	}

	// Rebuild the preference profile so engine strategies have fresh genre/actor/director data.
	// This is synchronous for now; could be moved to a background worker later.
	_ = h.profileUC.RebuildProfileFromFeedback(ctx, userID)

	return &analyticsv1.UpsertFeedbackResponse{FeedbackId: feedbackID.String()}, nil
}

func (h *FeedbackHandler) RemoveFeedback(ctx context.Context, req *analyticsv1.RemoveFeedbackRequest) (*emptypb.Empty, error) {
	id, err := uuid.Parse(req.GetFeedbackId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid feedback_id: %v", err)
	}
	if err := h.feedbackUC.RemoveFeedback(ctx, id); err != nil {
		return nil, domainErr(err)
	}
	return &emptypb.Empty{}, nil
}

func (h *FeedbackHandler) GetFeedback(ctx context.Context, req *analyticsv1.GetFeedbackRequest) (*analyticsv1.GetFeedbackResponse, error) {
	id, err := uuid.Parse(req.GetFeedbackId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid feedback_id: %v", err)
	}
	fb, err := h.feedbackUC.GetFeedback(ctx, id)
	if err != nil {
		return nil, domainErr(err)
	}
	return &analyticsv1.GetFeedbackResponse{Feedback: feedbackToProto(fb)}, nil
}

func (h *FeedbackHandler) ListUserFeedback(ctx context.Context, req *analyticsv1.ListUserFeedbackRequest) (*analyticsv1.ListUserFeedbackResponse, error) {
	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user_id: %v", err)
	}
	fbs, err := h.feedbackUC.ListUserFeedback(ctx, userID)
	if err != nil {
		return nil, domainErr(err)
	}
	protos := make([]*analyticsv1.Feedback, len(fbs))
	for i, fb := range fbs {
		protos[i] = feedbackToProto(fb)
	}
	return &analyticsv1.ListUserFeedbackResponse{Feedback: protos}, nil
}

func feedbackToProto(fb domain.MovieFeedback) *analyticsv1.Feedback {
	return &analyticsv1.Feedback{
		FeedbackId: fb.FeedbackID.String(),
		UserId:     fb.UserID.String(),
		MovieId:    fb.MovieID.String(),
		Rating:     fb.Rating,
		Title:      fb.Title,
		Content:    fb.Content,
	}
}
