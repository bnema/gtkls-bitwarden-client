// Package out defines the outbound ports (driven interfaces) for the application.
// These are the interfaces that the application layer depends on to interact with
// external systems. Implementations reside in internal/adapters.
package out

import (
	"context"
	"io"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
)

// RemoteVault abstracts the Bitwarden remote API. No SDK types leak.
type RemoteVault interface {
	Login(ctx context.Context, email, password string) error
	BeginLogin(ctx context.Context, email, password string) (*auth.TwoFactorChallenge, error)
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
}
