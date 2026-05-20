package http

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"movie_collection/internal/core/domain"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMapError(t *testing.T) {
	t.Parallel()

	existingStatus := status.Error(codes.PermissionDenied, "denied")

	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{
			name: "nil",
			err:  nil,
			code: codes.OK,
		},
		{
			name: "existing status passes through",
			err:  existingStatus,
			code: codes.PermissionDenied,
		},
		{
			name: "context canceled",
			err:  context.Canceled,
			code: codes.Canceled,
		},
		{
			name: "context deadline exceeded",
			err:  context.DeadlineExceeded,
			code: codes.DeadlineExceeded,
		},
		{
			name: "wrapped context canceled",
			err:  errors.Join(errors.New("query failed"), context.Canceled),
			code: codes.Canceled,
		},
		{
			name: "wrapped context deadline exceeded",
			err:  errors.Join(errors.New("query failed"), context.DeadlineExceeded),
			code: codes.DeadlineExceeded,
		},
		{
			name: "sql no rows",
			err:  sql.ErrNoRows,
			code: codes.NotFound,
		},
		{
			name: "invalid movie",
			err:  domain.ErrInvalidMovie,
			code: codes.InvalidArgument,
		},
		{
			name: "unknown",
			err:  errors.New("boom"),
			code: codes.Internal,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mapped := mapError(test.err)
			if status.Code(mapped) != test.code {
				t.Fatalf("unexpected code: got %s want %s", status.Code(mapped), test.code)
			}

			if test.err == nil && mapped != nil {
				t.Fatalf("expected nil error, got %v", mapped)
			}
		})
	}
}
