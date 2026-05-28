package logger

import (
	"context"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a single gRPC unary interceptor that:
//   - reads or generates a trace ID and stores it in ctx + outgoing logs,
//   - attaches a request-scoped logger to ctx (with grpc_method + trace_id),
//   - recovers panics into Internal errors with a stack trace logged,
//   - logs every call with grpc_method, code, duration_ms, and error.
//
// Chain order is fixed inside this single interceptor to keep wiring trivial
// in each main.go.
func UnaryServerInterceptor(base *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		traceID := incomingTraceID(ctx)
		ctx = WithTraceID(ctx, traceID)

		l := base.With("grpc_method", info.FullMethod, "trace_id", traceID)
		ctx = WithLogger(ctx, l)

		start := time.Now()

		defer func() {
			if r := recover(); r != nil {
				l.ErrorContext(ctx, "panic recovered",
					"panic", r,
					"stack", string(debug.Stack()),
				)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		resp, err = handler(ctx, req)

		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		attrs := []any{
			"code", code.String(),
			"duration_ms", time.Since(start).Milliseconds(),
		}
		if err != nil {
			attrs = append(attrs, "error", err.Error())
			l.LogAttrs(ctx, slog.LevelError, "grpc request", slogAttrs(attrs)...)
		} else {
			l.LogAttrs(ctx, slog.LevelInfo, "grpc request", slogAttrs(attrs)...)
		}

		return resp, err
	}
}

func incomingTraceID(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(TraceIDMetadataKey); len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return uuid.NewString()
}

func slogAttrs(kv []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, _ := kv[i].(string)
		out = append(out, slog.Any(key, kv[i+1]))
	}
	return out
}
