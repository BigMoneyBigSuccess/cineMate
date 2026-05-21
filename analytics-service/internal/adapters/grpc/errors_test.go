package grpc

import (
	"errors"
	"testing"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDomainErr_InvalidArgument_Errors(t *testing.T) {
	invalidArgErrors := []error{
		domain.ErrInvalidMovieFeedback,
		domain.ErrInvalidUserPreferenceProfile,
		domain.ErrInvalidMovieRecommendation,
		domain.ErrInvalidRecommendationRequest,
		domain.ErrInvalidRecommendationInteraction,
		domain.ErrInvalidGenre,
		domain.ErrInvalidPerson,
		domain.ErrInvalidMovieSnapshot,
		domain.ErrInvalidUserReference,
	}

	for _, domainError := range invalidArgErrors {
		err := domainErr(domainError)
		st, ok := status.FromError(err)
		if !ok {
			t.Errorf("%v: expected gRPC status error", domainError)
			continue
		}
		if st.Code() != codes.InvalidArgument {
			t.Errorf("%v: expected InvalidArgument, got %s", domainError, st.Code())
		}
	}
}

func TestDomainErr_InvalidMovieReference_MapsToNotFound(t *testing.T) {
	err := domainErr(domain.ErrInvalidMovieReference)
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.NotFound {
		t.Errorf("expected NotFound, got %s", st.Code())
	}
}

func TestDomainErr_UnknownError_MapsToInternal(t *testing.T) {
	err := domainErr(errors.New("some unexpected db error"))
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.Internal {
		t.Errorf("expected Internal, got %s", st.Code())
	}
}

func TestDomainErr_WrappedDomainError_StillMapsCorrectly(t *testing.T) {
	wrapped := errors.Join(domain.ErrInvalidMovieFeedback, errors.New("extra context"))
	err := domainErr(wrapped)
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.InvalidArgument {
		t.Errorf("wrapped domain error should map to InvalidArgument, got %s", st.Code())
	}
}

func TestDomainErr_PreservesErrorMessage(t *testing.T) {
	err := domainErr(domain.ErrInvalidMovieFeedback)
	st, _ := status.FromError(err)
	if st.Message() != domain.ErrInvalidMovieFeedback.Error() {
		t.Errorf("error message not preserved: expected %q, got %q",
			domain.ErrInvalidMovieFeedback.Error(), st.Message())
	}
}
