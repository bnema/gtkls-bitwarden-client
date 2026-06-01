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

// RemoteVault abstracts the Bitwarden remote API. No SDK types leak.
type RemoteVault interface {
	Login(ctx context.Context, email, password string, rememberedTwoFactorToken []byte) error
	BeginLogin(ctx context.Context, email, password string, rememberedTwoFactorToken []byte) (*auth.TwoFactorChallenge, error)
	CompleteTwoFactorLogin(ctx context.Context, challenge *auth.TwoFactorChallenge, provider auth.TwoFactorProvider, code string, remember bool) error
	CompleteTwoFactor(ctx context.Context, provider, code string, remember bool) error
	Lock(ctx context.Context) error
	Revision(ctx context.Context) (string, error)
	Sync(ctx context.Context) ([]vault.Item, []vault.Folder, string, error)

	Create(ctx context.Context, item vault.Item) (vault.Item, error)
	Update(ctx context.Context, id string, item vault.Item) (vault.Item, error)
	Trash(ctx context.Context, id string) error
	Restore(ctx context.Context, id string) (vault.Item, error)
	Delete(ctx context.Context, id string) error

	ListAttachments(ctx context.Context, itemID string) ([]vault.Attachment, error)
	DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) error
	UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (vault.Attachment, error)
	DeleteAttachment(ctx context.Context, itemID, attachmentID string) error

	// ExportSession returns the current unlocked session material and tokens.
	ExportSession(ctx context.Context) (session.UnlockMaterial, session.TokenBundle, error)
	// RestoreSession imports session material and tokens, unlocking the client.
	RestoreSession(ctx context.Context, material session.UnlockMaterial, tokens session.TokenBundle) error
	// RefreshTokenBundle refreshes the OAuth tokens for the account identified by the bundle.
	RefreshTokenBundle(ctx context.Context, tokens session.TokenBundle) (session.TokenBundle, error)
}
