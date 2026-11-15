//go:build darwin

package presence

import (
	"context"
	"errors"
	"fmt"

	"github.com/noamcohen97/touchid-go"
)

// confirm uses LAPolicyDeviceOwnerAuthentication: Touch ID where it is
// enrolled, else the login password. With no GUI session (SSH, a launchd
// job) LocalAuthentication reports it can't interact, and that is
// ErrUnavailable.
func confirm(ctx context.Context, reason string) error {
	err := touchid.Authenticate(ctx, touchid.PolicyDeviceOwnerAuthentication, reason)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, touchid.ErrNotInteractive), errors.Is(err, touchid.ErrPasscodeNotSet):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	case errors.Is(err, touchid.ErrUserCancel), errors.Is(err, touchid.ErrSystemCancel), errors.Is(err, touchid.ErrAppCancel):
		return fmt.Errorf("not confirmed: cancelled")
	default:
		return fmt.Errorf("not confirmed: %w", err)
	}
}
