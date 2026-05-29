package grpc

import (
	"errors"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func domainErr(err error) error {
	switch {
	case errors.Is(err, domain.ErrInvalidMovieFeedback),
		errors.Is(err, domain.ErrInvalidUserPreferenceProfile),
		errors.Is(err, domain.ErrInvalidMovieRecommendation),
		errors.Is(err, domain.ErrInvalidRecommendationRequest),
		errors.Is(err, domain.ErrInvalidRecommendationInteraction),
		errors.Is(err, domain.ErrInvalidGenre),
		errors.Is(err, domain.ErrInvalidPerson),
		errors.Is(err, domain.ErrInvalidMovieSnapshot),
		errors.Is(err, domain.ErrInvalidUserReference):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrInvalidMovieReference),
		errors.Is(err, domain.ErrFeedbackNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
