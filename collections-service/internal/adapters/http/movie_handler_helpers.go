package http

import (
	"context"
	"database/sql"
	"errors"
	"movie_collection/internal/core/domain"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func normalizeStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case status.Code(err) != codes.Unknown:
		return err
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, context.Canceled.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
	case errors.Is(err, sql.ErrNoRows):
		return status.Error(codes.NotFound, "movie not found")
	case errors.Is(err, domain.ErrInvalidMovie),
		errors.Is(err, domain.ErrInvalidGenre),
		errors.Is(err, domain.ErrInvalidPerson):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
