package bitwarden

import (
	"context"
	"errors"
	"io"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreauth "github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	corevault "github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/out"
)

// Compile-time check that Client satisfies out.RemoteVault.
var _ out.RemoteVault = (*Client)(nil)

// Package sentinel errors for operations the SDK does not support.
var (
	// ErrTwoFactorUnsupported is returned by CompleteTwoFactor because the
	// current RemoteVault port does not expose a two-factor challenge handle;
	// callers should use BeginLogin/CompleteLogin on the SDK directly.
	ErrTwoFactorUnsupported = errors.New("bitwarden: two-factor challenge not exposed by port, use BeginLogin/CompleteLogin directly")

	// ErrAttachmentsNotSupported is returned by ListAttachments because the
	// public SDK Item type does not expose an Attachments field. The SDK can
	// download/upload/delete attachments but cannot enumerate them at the item
	// level through the public API surface.
	ErrAttachmentsNotSupported = errors.New("bitwarden: attachment enumeration not supported by SDK—use DownloadAttachment with known IDs")
)

// Client wraps the Bitwarden Go SDK to implement the out.RemoteVault port.
type Client struct {
	sdk *sdk.Client
}

// NewClient creates a new adapter Client wrapping the SDK, configured from a
// core config. Additional SDK options may be appended (e.g. for testing).
func NewClient(cfg *coreconfig.Config, opts ...sdk.Option) (*Client, error) {
	var sdkOpts []sdk.Option

	switch cfg.Bitwarden.Region {
	case coreconfig.RegionSelfHosted:
		if cfg.Bitwarden.ServerURL != "" {
			sdkOpts = append(sdkOpts, sdk.WithServerURL(cfg.Bitwarden.ServerURL))
		}
	default:
		sdkOpts = append(sdkOpts, sdk.WithRegion(toSDKRegion(cfg.Bitwarden.Region)))
	}

	sdkOpts = append(sdkOpts, opts...)

	sdkClient, err := sdk.NewClient(sdkOpts...)
	if err != nil {
		return nil, err
	}

	return &Client{sdk: sdkClient}, nil
}

// NewFromSDK wraps an existing SDK client. Useful for tests and future wiring.
func NewFromSDK(client *sdk.Client) *Client {
	return &Client{sdk: client}
}

// Login authenticates with master password.
func (c *Client) Login(ctx context.Context, email, password string) error {
	return c.sdk.Login(ctx, sdk.LoginOptions{Email: email, Password: password})
}

// BeginLogin starts login and returns a two-factor challenge when required.
func (c *Client) BeginLogin(ctx context.Context, email, password string) (*coreauth.TwoFactorChallenge, error) {
	result, err := c.sdk.BeginLogin(ctx, sdk.LoginOptions{Email: email, Password: password})
	if err != nil {
		return nil, err
	}
	if result.Challenge == nil {
		return nil, nil
	}
	providers := make([]coreauth.TwoFactorProvider, 0, len(result.Challenge.Providers()))
	for _, provider := range result.Challenge.Providers() {
		providers = append(providers, fromSDKProvider(provider))
	}
	challenge := result.Challenge
	return coreauth.NewTwoFactorChallenge(providers, challenge, challenge.Close), nil
}

// CompleteTwoFactorLogin completes a challenge returned by BeginLogin.
func (c *Client) CompleteTwoFactorLogin(ctx context.Context, challenge *coreauth.TwoFactorChallenge, provider coreauth.TwoFactorProvider, code string, remember bool) error {
	if challenge == nil {
		return ErrTwoFactorUnsupported
	}
	sdkChallenge, ok := challenge.Handle.(*sdk.TwoFactorChallenge)
	if !ok || sdkChallenge == nil {
		return ErrTwoFactorUnsupported
	}
	_, err := c.sdk.CompleteLogin(ctx, sdk.CompleteLoginOptions{
		Challenge: sdkChallenge,
		Provider:  toSDKProvider(provider),
		Code:      code,
		Remember:  remember,
	})
	return err
}

// CompleteTwoFactor returns ErrTwoFactorUnsupported because callers need the
// challenge returned by BeginLogin.
func (c *Client) CompleteTwoFactor(_ context.Context, _, _ string, _ bool) error {
	return ErrTwoFactorUnsupported
}

func fromSDKProvider(provider sdk.TwoFactorProvider) coreauth.TwoFactorProvider {
	switch provider {
	case sdk.TwoFactorProviderAuthenticator:
		return coreauth.TwoFactorProviderAuthenticator
	case sdk.TwoFactorProviderEmail:
		return coreauth.TwoFactorProviderEmail
	case sdk.TwoFactorProviderYubiKey:
		return coreauth.TwoFactorProviderYubiKey
	case sdk.TwoFactorProviderDuo:
		return coreauth.TwoFactorProviderDuo
	default:
		return coreauth.TwoFactorProvider(provider)
	}
}

func toSDKProvider(provider coreauth.TwoFactorProvider) sdk.TwoFactorProvider {
	switch provider {
	case coreauth.TwoFactorProviderAuthenticator:
		return sdk.TwoFactorProviderAuthenticator
	case coreauth.TwoFactorProviderEmail:
		return sdk.TwoFactorProviderEmail
	case coreauth.TwoFactorProviderYubiKey:
		return sdk.TwoFactorProviderYubiKey
	case coreauth.TwoFactorProviderDuo:
		return sdk.TwoFactorProviderDuo
	default:
		return sdk.TwoFactorProvider(provider)
	}
}

// Lock locks the vault client, clearing in-memory key material.
func (c *Client) Lock(_ context.Context) error {
	c.sdk.Lock()
	return nil
}

// Revision returns an opaque revision string.
//
// The SDK (v0.1.0) has no public revision-date or revision-check endpoint.
// Because we cannot obtain a stable token to compare against, every call
// forces a full sync. Returning "unknown" (a non-empty sentinel that never
// matches any real token) ensures the caller always detects a change and
// triggers Sync. Do NOT fake a stable token here — that would suppress syncs
// and cause stale state.
func (c *Client) Revision(_ context.Context) (string, error) {
	return "unknown", nil
}

// Sync refreshes vault state from the server and returns all items, folders,
// and an opaque revision string.
func (c *Client) Sync(ctx context.Context) ([]corevault.Item, []corevault.Folder, string, error) {
	if err := c.sdk.Sync(ctx); err != nil {
		return nil, nil, "", err
	}

	sdkItems, err := c.sdk.Vault().List(ctx)
	if err != nil {
		return nil, nil, "", err
	}

	sdkFolders, err := c.sdk.Folders().List(ctx)
	if err != nil {
		return nil, nil, "", err
	}

	items := make([]corevault.Item, 0, len(sdkItems))
	for _, si := range sdkItems {
		ci, err := toCoreItem(si)
		if err != nil {
			return nil, nil, "", err
		}
		items = append(items, ci)
	}

	folders := make([]corevault.Folder, len(sdkFolders))
	for i, sf := range sdkFolders {
		folders[i] = toCoreFolder(sf)
	}

	return items, folders, "unknown", nil
}

// Create creates a new vault item.
func (c *Client) Create(ctx context.Context, item corevault.Item) (corevault.Item, error) {
	created, err := c.sdk.Vault().Create(ctx, toSDKItem(item))
	if err != nil {
		return corevault.Item{}, err
	}
	return toCoreItem(created)
}

// Update updates an existing vault item by ID.
func (c *Client) Update(ctx context.Context, id string, item corevault.Item) (corevault.Item, error) {
	updated, err := c.sdk.Vault().Update(ctx, sdk.ItemID(id), toSDKItem(item))
	if err != nil {
		return corevault.Item{}, err
	}
	return toCoreItem(updated)
}

// Trash soft-deletes (trashes) a vault item.
func (c *Client) Trash(ctx context.Context, id string) error {
	return c.sdk.Vault().Trash(ctx, sdk.ItemID(id))
}

// Restore restores a trashed vault item.
func (c *Client) Restore(ctx context.Context, id string) (corevault.Item, error) {
	restored, err := c.sdk.Vault().Restore(ctx, sdk.ItemID(id))
	if err != nil {
		return corevault.Item{}, err
	}
	return toCoreItem(restored)
}

// Delete permanently deletes a vault item.
func (c *Client) Delete(ctx context.Context, id string) error {
	return c.sdk.Vault().Delete(ctx, sdk.ItemID(id))
}

// ListAttachments returns ErrAttachmentsNotSupported because the public SDK
// Item type does not expose an Attachments field. The SDK can
// download/upload/delete individual attachments by known ID but cannot
// enumerate them at the item level through the public API surface.
func (c *Client) ListAttachments(_ context.Context, _ string) ([]corevault.Attachment, error) {
	return nil, ErrAttachmentsNotSupported
}

// DownloadAttachment downloads and decrypts an attachment to dst.
func (c *Client) DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) error {
	return c.sdk.Attachments().Download(ctx, itemID, attachmentID, dst)
}

// UploadAttachment encrypts and uploads an attachment from src.
func (c *Client) UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (corevault.Attachment, error) {
	opts := sdk.AttachmentUploadOptions{
		ItemID:   itemID,
		FileName: fileName,
		Size:     size,
		Reader:   src,
	}
	att, err := c.sdk.Attachments().Upload(ctx, opts)
	if err != nil {
		return corevault.Attachment{}, err
	}
	return toCoreAttachment(att), nil
}

// DeleteAttachment deletes an attachment.
func (c *Client) DeleteAttachment(ctx context.Context, itemID, attachmentID string) error {
	return c.sdk.Attachments().Delete(ctx, itemID, attachmentID)
}
