// Package compose is the composition root for production adapters. It builds
// the application service and the local-data and configuration helpers the CLI
// needs, so driving adapters (CLI, GUI) depend on ports rather than on concrete
// storage, keyring, or remote implementations.
package compose

import (
	"context"
	"fmt"

	cryptobox "github.com/bnema/gtkls-bitwarden-client/internal/adapters/cache/crypto"
	cachefile "github.com/bnema/gtkls-bitwarden-client/internal/adapters/cache/file"
	remoteadapter "github.com/bnema/gtkls-bitwarden-client/internal/adapters/remote/bitwarden"
	keyring "github.com/bnema/gtkls-bitwarden-client/internal/adapters/secrets/keyring"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/session/bootid"
	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/session/pinenvelope"
	"github.com/bnema/gtkls-bitwarden-client/internal/app"
	viperadapter "github.com/bnema/gtkls-bitwarden-client/internal/app/viper"
	coreconfig "github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

// ConfigManager is the configuration store used by the CLI: the persistence
// port plus the backing file path.
type ConfigManager interface {
	out.ConfigStore
	Path() string
}

// NewConfigManager returns the file-backed configuration manager for path.
// An empty path selects the default user configuration file.
func NewConfigManager(path string) ConfigManager {
	return viperadapter.NewManager(path)
}

// Service builds the production application service from the given config.
// cachePath and outboxPath should be computed once by the caller.
func Service(ctx context.Context, cfg *coreconfig.Config, cachePath, outboxPath string) (in.AppService, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Secret box for cache/outbox encryption.
	box := cryptobox.NewBox()

	// File-backed cache and outbox stores.
	cacheStore := cachefile.NewStore(cachePath)
	outboxStore := cachefile.NewOutboxStore(outboxPath, box)

	// Bitwarden remote adapter.
	remote, err := remoteadapter.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("remote client: %w", err)
	}

	return app.NewService(app.Deps{
		Remote:      remote,
		Cache:       cacheStore,
		Outbox:      outboxStore,
		SecretBox:   box,
		Config:      cfg,
		Credentials: keyring.New(),
		BootID:      bootid.New(),
		PINEnvelope: pinenvelope.New(pinenvelope.ServiceConfig{}),
		// Clock can be nil; service falls back to time.Now.
	}), nil
}

// ClearLocalData removes the encrypted cache and outbox files.
func ClearLocalData(ctx context.Context, cachePath, outboxPath string) error {
	box := cryptobox.NewBox()
	cacheStore := cachefile.NewStore(cachePath)
	outboxStore := cachefile.NewOutboxStore(outboxPath, box)

	if err := cacheStore.Clear(ctx); err != nil {
		return fmt.Errorf("cache clear: %w", err)
	}
	if err := outboxStore.Clear(ctx); err != nil {
		return fmt.Errorf("outbox clear: %w", err)
	}
	return nil
}
