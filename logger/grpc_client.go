package logger

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if id := TraceIDFromContext(ctx); id != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, TraceIDMetadataKey, id)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
