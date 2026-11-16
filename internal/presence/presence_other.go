//go:build !darwin

package presence

import "context"

// confirm has no implementation outside macOS yet, so callers fail closed.
func confirm(context.Context, string) error {
	return ErrUnavailable
}
