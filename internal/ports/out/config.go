package out

import (
	"context"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
)

// ConfigStore persists and watches application configuration.
type ConfigStore interface {
	Load(ctx context.Context) (*config.Config, error)
	Save(ctx context.Context, cfg *config.Config) error
	Watch(ctx context.Context, onChange func(*config.Config)) error
}
