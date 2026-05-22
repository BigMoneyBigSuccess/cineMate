package ports

import "context"

// AIClient is the outbound boundary to a large-language-model provider.
// It accepts a fully-formed prompt and returns the model's text reply.
type AIClient interface {
	Complete(ctx context.Context, prompt string) (string, error)
}
