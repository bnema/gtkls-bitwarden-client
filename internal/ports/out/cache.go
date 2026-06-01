package out

import (
	"context"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/cache"
)

// CacheStore persists and retrieves encrypted vault snapshots.
type CacheStore interface {
	Load(ctx context.Context) (cache.Snapshot, error)
	Save(ctx context.Context, snapshot cache.Snapshot) error
	Clear(ctx context.Context) error
	Path() string
}
