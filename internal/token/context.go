package token

import "context"

type contextKey struct{}

// WithTokenID returns a new context with the given token ID attached.
func WithTokenID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// TokenIDFromContext extracts the token ID from the context, if any.
func TokenIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKey{}).(string)
	return id, ok && id != ""
}
