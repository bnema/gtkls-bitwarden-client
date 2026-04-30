// Package in defines the inbound ports (driving interfaces) for the application.
// These are the interfaces that external adapters (UI, CLI) depend on.
// Implementations reside in internal/app; no adapter types leak here.
package in

import (
	"context"
	"io"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/sync"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
)

// EventKind categorises events emitted by the application layer.
type EventKind string

const (
	Locked           EventKind = "locked"
	Unlocking        EventKind = "unlocking"
	CacheLoaded      EventKind = "cache_loaded"
	IndexReady       EventKind = "index_ready"
	SyncChecking     EventKind = "sync_checking"
	SyncUpdated      EventKind = "sync_updated"
	SyncFailed       EventKind = "sync_failed"
	MutationPending  EventKind = "mutation_pending"
	ConflictDetected EventKind = "conflict_detected"
	Relocked         EventKind = "relocked"
)

// Event represents a domain event emitted by the application layer.
type Event struct {
	Kind    EventKind
	Message string
	Count   int
}

// AppService is the primary inbound port. Every UI or CLI adapter drives the
// application through this interface.
type AppService interface {
	Unlock(ctx context.Context, email, password string) error
	UnlockWithTwoFactor(ctx context.Context, email, password string, prompt auth.TwoFactorPrompt) error
	Lock(ctx context.Context) error
	Search(ctx context.Context, query string, limit int) ([]vault.ScoredItem, error)
	Items(ctx context.Context) ([]vault.Item, error)
	Get(ctx context.Context, id string) (vault.Item, error)
	Create(ctx context.Context, item vault.Item) (vault.Item, error)
	Update(ctx context.Context, id string, item vault.Item) (vault.Item, error)
	Trash(ctx context.Context, id string) error
	Restore(ctx context.Context, id string) (vault.Item, error)
	Delete(ctx context.Context, id string) error
	ListAttachments(ctx context.Context, itemID string) ([]vault.Attachment, error)
	DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) error
	UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (vault.Attachment, error)
	DeleteAttachment(ctx context.Context, itemID, attachmentID string) error
	ResolveConflict(ctx context.Context, conflictID string, resolution sync.ConflictResolution) error
	Config() *config.Config
	UpdateConfig(ctx context.Context, cfg *config.Config) error
	Events() <-chan Event
	Shutdown(ctx context.Context) error
}
