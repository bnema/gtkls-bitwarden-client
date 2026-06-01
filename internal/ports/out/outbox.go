package out

import (
	"context"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
)

// OutboxStore persists pending local mutations for offline-first sync.
type OutboxStore interface {
	Load(ctx context.Context, key []byte) ([]sync.OutboxMutation, error)
	Save(ctx context.Context, key []byte, mutations []sync.OutboxMutation) error
}
