package omnibox

import (
	"context"
	"errors"
	"time"

	clipadapter "github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/clipboard"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/out"
)

var (
	errPrimaryActionUnavailable     = errors.New("primary action clipboard value unavailable")
	errPrimaryActionRequiresLogin   = errors.New("primary action requires a login item")
	errPrimaryActionPasswordMissing = errors.New("primary action password unavailable")
	errPrimaryActionUsernameMissing = errors.New("primary action username unavailable")
)

func primaryActionClipboardTTL(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	return cfg.Actions.ClipboardClearAfter
}

func primaryActionErrorStatus(action Action, err error) string {
	switch {
	case errors.Is(err, errPrimaryActionPasswordMissing):
		return "No password stored for this item"
	case errors.Is(err, errPrimaryActionUsernameMissing):
		return "No username stored for this item"
	case errors.Is(err, errPrimaryActionRequiresLogin):
		switch action {
		case ActionCopyUsername:
			return "Username copy works on login items only"
		default:
			return "Password copy works on login items only"
		}
	case errors.Is(err, clipadapter.ErrClipboardUnavailable):
		return "Clipboard unavailable"
	default:
		return "Could not copy to clipboard"
	}
}

func copyPrimaryAction(ctx context.Context, clipboard out.Clipboard, item vault.Item, action Action, ttl time.Duration) (string, error) {
	if clipboard == nil {
		return "", clipadapter.ErrClipboardUnavailable
	}
	if item.Login == nil {
		return "", errPrimaryActionRequiresLogin
	}

	var text string
	var status string
	switch action {
	case ActionCopyPassword:
		text = item.Login.Password
		status = "Password copied"
	case ActionCopyUsername:
		text = item.Login.Username
		status = "Username copied"
	default:
		return "", errPrimaryActionUnavailable
	}
	if text == "" {
		switch action {
		case ActionCopyUsername:
			return "", errPrimaryActionUsernameMissing
		default:
			return "", errPrimaryActionPasswordMissing
		}
	}
	if err := clipboard.Set(ctx, text, ttl); err != nil {
		return "", err
	}
	return status, nil
}
