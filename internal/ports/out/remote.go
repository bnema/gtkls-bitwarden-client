// Package out defines the outbound ports (driven interfaces) for the application.
// These are the interfaces that the application layer depends on to interact with
// external systems. Implementations reside in internal/adapters.
package out

import (
	"context"
	"io"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/auth"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/session"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

// RemoteAuth covers remote login and lock. Login is always a begin/complete
// pair: BeginLogin returns a non-nil challenge when two-factor authentication
// is required, and CompleteTwoFactorLogin finishes it.
type RemoteAuth interface {
	BeginLogin(ctx context.Context, email, password string, rememberedTwoFactorToken []byte) (*auth.TwoFactorChallenge, error)
	CompleteTwoFactorLogin(ctx context.Context, challenge *auth.TwoFactorChallenge, provider auth.TwoFactorProvider, code string, remember bool) error
	Lock(ctx context.Context) error
}

// RemoteSession moves unlocked session material and OAuth tokens in and out of
// the remote client.
type RemoteSession interface {
	// ExportSession returns the current unlocked session material and tokens.
	ExportSession(ctx context.Context) (session.UnlockMaterial, session.TokenBundle, error)
	// RestoreSession imports session material and tokens, unlocking the client.
	RestoreSession(ctx context.Context, material session.UnlockMaterial, tokens session.TokenBundle) error
	// RefreshTokenBundle refreshes the OAuth tokens for the account identified by the bundle.
	RefreshTokenBundle(ctx context.Context, tokens session.TokenBundle) (session.TokenBundle, error)
}

// RemoteSync reads vault state from the remote.
type RemoteSync interface {
	Revision(ctx context.Context) (string, error)
	Sync(ctx context.Context) ([]vault.Item, []vault.Folder, string, error)
}

// RemoteItems mutates vault items on the remote.
type RemoteItems interface {
	Create(ctx context.Context, item vault.Item) (vault.Item, error)
	Update(ctx context.Context, id string, item vault.Item) (vault.Item, error)
	Trash(ctx context.Context, id string) error
	Restore(ctx context.Context, id string) (vault.Item, error)
	Delete(ctx context.Context, id string) error
}

// RemoteAttachments manages item attachments on the remote. Implementations may
// not support every operation (for example enumeration).
type RemoteAttachments interface {
	ListAttachments(ctx context.Context, itemID string) ([]vault.Attachment, error)
	DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) error
	UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (vault.Attachment, error)
	DeleteAttachment(ctx context.Context, itemID, attachmentID string) error
}

// RemoteVault is the composite the application service is wired with. It
// bundles every remote capability the service uses; attachments are not part of
// it because the service does not use them yet. No SDK types leak.
type RemoteVault interface {
	RemoteAuth
	RemoteSession
	RemoteSync
	RemoteItems
}
