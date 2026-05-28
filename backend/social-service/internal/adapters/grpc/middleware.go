package grpc

import (
	"context"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/clients"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const userIDContextKey contextKey = "user_id"

var openMethods = map[string]bool{
	"/social.v1.SocialService/CreateProfile": true,
	"/social.v1.SocialService/GetProfile":    true,
	"/social.v1.SocialService/GetFollowers":  true,
	"/social.v1.SocialService/GetFollowing":  true,
	"/social.v1.SocialService/IsFollowing":   true,
	"/social.v1.SocialService/SearchUsers":   true,
}

func AuthUnaryInterceptor(authClient *clients.AuthClient) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if openMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization header is required")
		}

		token := strings.TrimSpace(authHeaders[0])
		if strings.HasPrefix(strings.ToLower(token), "bearer ") {
			token = strings.TrimSpace(token[7:])
		}

		userID, valid, errMsg := authClient.ValidateToken(ctx, token)
		if !valid {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %s", errMsg)
		}

		ctx = context.WithValue(ctx, userIDContextKey, userID)
		return handler(ctx, req)
	}
}

func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDContextKey).(uuid.UUID)
	return id, ok
}
