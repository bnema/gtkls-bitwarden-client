package app

import (
	"context"
	"sync"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/config"
	coresync "github.com/bnema/gtkls-bitwarden-client/internal/core/sync"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

// Deps holds the external dependencies the service needs.
type Deps struct {
	Remote      out.RemoteVault
	Cache       out.CacheStore
	SecretBox   out.SecretBox
	Outbox      out.OutboxStore
	Clock       out.Clock
	Config      *config.Config
	Credentials out.CredentialStore
	BootID      out.BootIDProvider
	PINEnvelope out.PINEnvelopeService
}

// Service implements the application's core business logic.
type Service struct {
	mu                      sync.Mutex
	cacheSaveMu             sync.Mutex
	saveSeq                 uint64
	saveWG                  sync.WaitGroup
	eventMu                 sync.RWMutex
	eventsClosed            bool
	cfg                     *config.Config
	state                   auth.LockState
	lifecycle               uint64
	cacheKey                []byte
	cacheSalt               []byte
	outboxSeq               uint64
	items                   []vault.Item
	folders                 []vault.Folder
	outbox                  []coresync.OutboxMutation
	conflicts               []coresync.Conflict
	index                   *vault.SearchIndex
	events                  chan Event
	cancelWorkers           context.CancelFunc
	backgroundSyncMode      backgroundSyncMode
	backgroundSyncSuspended bool
	deps                    Deps

	pendingRemoteItems   []vault.Item
	pendingRemoteFolders []vault.Folder
}
