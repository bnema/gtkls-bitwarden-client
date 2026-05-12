package omnibox

import (
	"context"
	"errors"
	"testing"
	"time"

	clipadapter "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/clipboard"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/stretchr/testify/require"
)

type primaryActionClipboard struct {
	text string
	ttl  time.Duration
	err  error
}

func (c *primaryActionClipboard) Set(_ context.Context, text string, ttl time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.text = text
	c.ttl = ttl
	return nil
}

func (c *primaryActionClipboard) Clear(context.Context) error { return nil }

func TestCopyPrimaryActionPasswordUsesClipboard(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeLogin, Login: &vault.Login{Username: "user@example.com", Password: "secret-password"}}
	clip := &primaryActionClipboard{}
	ttl := 45 * time.Second

	status, err := copyPrimaryAction(context.Background(), clip, item, ActionCopyPassword, ttl)

	require.NoError(t, err)
	require.Equal(t, "Password copied", status)
	require.Equal(t, "secret-password", clip.text)
	require.Equal(t, ttl, clip.ttl)
}

func TestCopyPrimaryActionUsernameUsesClipboard(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeLogin, Login: &vault.Login{Username: "user@example.com", Password: "secret-password"}}
	clip := &primaryActionClipboard{}
	ttl := 30 * time.Second

	status, err := copyPrimaryAction(context.Background(), clip, item, ActionCopyUsername, ttl)

	require.NoError(t, err)
	require.Equal(t, "Username copied", status)
	require.Equal(t, "user@example.com", clip.text)
	require.Equal(t, ttl, clip.ttl)
}

func TestCopyPrimaryActionReturnsClipboardErrorWithoutSuccessStatus(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeLogin, Login: &vault.Login{Password: "secret-password"}}
	clip := &primaryActionClipboard{err: errors.New("clipboard unavailable")}

	status, err := copyPrimaryAction(context.Background(), clip, item, ActionCopyPassword, time.Minute)

	require.Error(t, err)
	require.Empty(t, status)
	require.Empty(t, clip.text)
}

func TestCopyPrimaryActionRejectsMissingSecret(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeLogin, Login: &vault.Login{}}
	clip := &primaryActionClipboard{}

	status, err := copyPrimaryAction(context.Background(), clip, item, ActionCopyPassword, time.Minute)

	require.ErrorIs(t, err, errPrimaryActionPasswordMissing)
	require.Empty(t, status)
	require.Empty(t, clip.text)
}

func TestCopyPrimaryActionRejectsMissingUsername(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeLogin, Login: &vault.Login{Password: "secret-password"}}
	clip := &primaryActionClipboard{}

	status, err := copyPrimaryAction(context.Background(), clip, item, ActionCopyUsername, time.Minute)

	require.ErrorIs(t, err, errPrimaryActionUsernameMissing)
	require.Empty(t, status)
	require.Empty(t, clip.text)
}

func TestCopyPrimaryActionRejectsNonLoginItems(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeSecureNote}
	clip := &primaryActionClipboard{}

	status, err := copyPrimaryAction(context.Background(), clip, item, ActionCopyPassword, time.Minute)

	require.ErrorIs(t, err, errPrimaryActionRequiresLogin)
	require.Empty(t, status)
	require.Empty(t, clip.text)
}

func TestCopyPrimaryActionRejectsMissingClipboardBackend(t *testing.T) {
	item := vault.Item{ID: "item-1", Type: vault.ItemTypeLogin, Login: &vault.Login{Password: "secret-password"}}

	status, err := copyPrimaryAction(context.Background(), nil, item, ActionCopyPassword, time.Minute)

	require.ErrorIs(t, err, clipadapter.ErrClipboardUnavailable)
	require.Empty(t, status)
}

func TestPrimaryActionErrorStatus(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		err    error
		want   string
	}{
		{name: "missing password", action: ActionCopyPassword, err: errPrimaryActionPasswordMissing, want: "No password stored for this item"},
		{name: "missing username", action: ActionCopyUsername, err: errPrimaryActionUsernameMissing, want: "No username stored for this item"},
		{name: "non-login password copy", action: ActionCopyPassword, err: errPrimaryActionRequiresLogin, want: "Password copy works on login items only"},
		{name: "non-login username copy", action: ActionCopyUsername, err: errPrimaryActionRequiresLogin, want: "Username copy works on login items only"},
		{name: "clipboard unavailable", action: ActionCopyPassword, err: clipadapter.ErrClipboardUnavailable, want: "Clipboard unavailable"},
		{name: "clipboard write failed", action: ActionCopyPassword, err: errors.New("clipboard write failed"), want: "Could not copy to clipboard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, primaryActionErrorStatus(tt.action, tt.err))
		})
	}
}

func TestPrimaryActionTTLFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Actions.ClipboardClearAfter = 12 * time.Second

	require.Equal(t, 12*time.Second, primaryActionClipboardTTL(cfg))
	require.Zero(t, primaryActionClipboardTTL(nil))
}
