package logger

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
)

func HTTPMiddleware(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			traceID := r.Header.Get(TraceIDMetadataKey)
			if traceID == "" {
				traceID = uuid.NewString()
			}
			w.Header().Set(TraceIDMetadataKey, traceID)

			ctx := WithTraceID(r.Context(), traceID)
			l := base.With(
				"trace_id", traceID,
				"http_method", r.Method,
				"path", r.URL.Path,
			)
			ctx = WithLogger(ctx, l)

			start := time.Now()
			rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

			defer func() {
				if rec := recover(); rec != nil {
					l.ErrorContext(ctx, "panic recovered",
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					if !rw.written {
						http.Error(rw, "internal server error", http.StatusInternalServerError)
					}
				}

				attrs := []any{
					"status", rw.status,
					"duration_ms", time.Since(start).Milliseconds(),
				}
				if rw.status >= http.StatusInternalServerError {
					l.LogAttrs(ctx, slog.LevelError, "http request", slogAttrs(attrs)...)
				} else {
					l.LogAttrs(ctx, slog.LevelInfo, "http request", slogAttrs(attrs)...)
				}
			}()

			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

type responseRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.written = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.written = true
	return r.ResponseWriter.Write(b)
}
