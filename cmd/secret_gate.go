package cmd

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/nokey-ai/nokey/internal/approval"
	"github.com/nokey-ai/nokey/internal/keyring"
)

// confirmSecretChange is the human gate for CLI commands that rename,
// remove or replace stored secrets. Policy rules match secret names and
// commands trust the values behind them, so a program running as the user
// must not be able to move a secret under another rule, swap its value or
// destroy it. existing are the stored secrets the change touches; with
// none there is nothing to protect and no prompt.
func confirmSecretChange(ctx context.Context, store *keyring.Store, action string, existing []string) error {
	if len(existing) == 0 {
		return nil
	}
	return confirmHuman(ctx, store, fmt.Sprintf("%s %s", action, approval.Quote(strings.Join(existing, ", "))), false)
}

// storedAmong returns the names that are stored secrets, in the order
// given. It reads names only, never a value.
func storedAmong(store *keyring.Store, names ...string) ([]string, error) {
	stored, err := store.List()
	if err != nil {
		return nil, err
	}
	var found []string
	for _, name := range names {
		if slices.Contains(stored, name) {
			found = append(found, name)
		}
	}
	return found, nil
}
