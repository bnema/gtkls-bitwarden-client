package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreauth "github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
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
	sdk        *sdk.Client
	httpClient *http.Client // optional; used by RefreshTokenBundle when creating refresh sub-clients
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

// NewFromSDKWithHTTPClient wraps an existing SDK client and sets the HTTP
// client that RefreshTokenBundle uses when creating refresh sub-clients.
func NewFromSDKWithHTTPClient(client *sdk.Client, hc *http.Client) *Client {
	return &Client{sdk: client, httpClient: hc}
}

// Login authenticates with master password.
func (c *Client) Login(ctx context.Context, email, password string) error {
	return c.sdk.Login(ctx, loginOptions(email, password))
}

// BeginLogin starts login and returns a two-factor challenge when required.
func (c *Client) BeginLogin(ctx context.Context, email, password string) (*coreauth.TwoFactorChallenge, error) {
	result, err := c.sdk.BeginLogin(ctx, loginOptions(email, password))
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

func loginOptions(email, password string) sdk.LoginOptions {
	return sdk.LoginOptions{
		Email:            email,
		Password:         password,
		DeviceType:       "LinuxDesktop",
		DeviceIdentifier: "gtk4-layershell-bitwarden",
		DeviceName:       "gtk4-layershell-bitwarden",
	}
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

// ExportSession returns the current unlocked session material and tokens.
func (c *Client) ExportSession(ctx context.Context) (coresession.UnlockMaterial, coresession.TokenBundle, error) {
	if c == nil || c.sdk == nil {
		return coresession.UnlockMaterial{}, coresession.TokenBundle{}, errors.New("bitwarden adapter: client or SDK is nil")
	}

	sdkMaterial, err := c.sdk.ExportSession(ctx)
	if err != nil {
		return coresession.UnlockMaterial{}, coresession.TokenBundle{}, err
	}
	defer sdkMaterial.Close()

	material := coresession.UnlockMaterial{
		UserKey: make([]byte, len(sdkMaterial.UserKey)),
	}
	copy(material.UserKey, sdkMaterial.UserKey)

	tokens := coresession.TokenBundle{
		AccountID:    sdkMaterial.Tokens.AccountID,
		AccessToken:  make([]byte, len(sdkMaterial.Tokens.AccessToken)),
		RefreshToken: make([]byte, len(sdkMaterial.Tokens.RefreshToken)),
		TokenType:    sdkMaterial.Tokens.TokenType,
		ExpiresAt:    sdkMaterial.Tokens.ExpiresAt,
	}
	copy(tokens.AccessToken, sdkMaterial.Tokens.AccessToken)
	copy(tokens.RefreshToken, sdkMaterial.Tokens.RefreshToken)

	return material, tokens, nil
}

// RestoreSession imports session material and tokens, unlocking the client.
func (c *Client) RestoreSession(ctx context.Context, material coresession.UnlockMaterial, tokens coresession.TokenBundle) error {
	if c == nil || c.sdk == nil {
		return errors.New("bitwarden adapter: client or SDK is nil")
	}
	if tokens.AccountID == "" {
		return fmt.Errorf("bitwarden adapter: TokenBundle.AccountID must not be empty")
	}

	sdkMaterial := sdk.SessionMaterial{
		AccountID: tokens.AccountID,
		UserKey:   make([]byte, len(material.UserKey)),
		Tokens: sdk.TokenSet{
			AccountID:    tokens.AccountID,
			AccessToken:  make([]byte, len(tokens.AccessToken)),
			RefreshToken: make([]byte, len(tokens.RefreshToken)),
			TokenType:    tokens.TokenType,
			ExpiresAt:    tokens.ExpiresAt,
		},
	}
	copy(sdkMaterial.UserKey, material.UserKey)
	copy(sdkMaterial.Tokens.AccessToken, tokens.AccessToken)
	copy(sdkMaterial.Tokens.RefreshToken, tokens.RefreshToken)
	defer sdkMaterial.Close()

	return c.sdk.RestoreSession(ctx, sdkMaterial)
}

// classifyServerIdentity classifies a server URL into a region (US/EU) or
// self-hosted URL. US cloud URL and empty string map to RegionUS;
// EU cloud URL maps to RegionEU; everything else is self-hosted.
func classifyServerIdentity(serverURL string) (region sdk.Region, selfHosted string) {
	normalized := strings.TrimRight(serverURL, "/")
	switch normalized {
	case "", "https://vault.bitwarden.com":
		region = sdk.RegionUS
	case "https://vault.bitwarden.eu":
		region = sdk.RegionEU
	default:
		selfHosted = serverURL
	}
	return
}

// serverIdentityOption returns the SDK option to connect to the Bitwarden
// identity service for the given server URL.
func serverIdentityOption(serverURL string) sdk.Option {
	region, selfHosted := classifyServerIdentity(serverURL)
	if selfHosted != "" {
		return sdk.WithServerURL(selfHosted)
	}
	return sdk.WithRegion(region)
}

// refreshTokenStore implements sdk.TokenStore with an in-memory map so that
// RefreshTokenBundle can seed a new SDK client with the caller's tokens. It
// holds a pre-seeded Load set plus a captured Save result.
type refreshTokenStore struct {
	mu     sync.Mutex
	toLoad sdk.TokenSet
}

func newRefreshTokenStore(seeds sdk.TokenSet) *refreshTokenStore {
	return &refreshTokenStore{toLoad: seeds}
}

func (s *refreshTokenStore) LoadTokens(_ context.Context, accountID string) (sdk.TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toLoad.AccountID != accountID {
		return sdk.TokenSet{}, fmt.Errorf("bitwarden adapter: account %q not found in refresh token store", accountID)
	}
	return s.toLoad.Clone(), nil
}

func (s *refreshTokenStore) SaveTokens(_ context.Context, tokens sdk.TokenSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := tokens.Clone()
	// Also update toLoad for future reads.
	s.toLoad.Close()
	s.toLoad = cloned
	return nil
}

func (s *refreshTokenStore) DeleteTokens(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.toLoad.AccountID == accountID {
		s.toLoad.Close()
		s.toLoad = sdk.TokenSet{}
	}
	return nil
}

// RefreshTokenBundle refreshes the OAuth tokens for the account identified
// by the bundle. It constructs a new SDK client for the bundle's server
// identity, seeds the token store with the supplied bundle, calls refresh,
// and returns the updated TokenBundle with original Email and ServerURL metadata
// preserved.
func (c *Client) RefreshTokenBundle(ctx context.Context, tokens coresession.TokenBundle) (coresession.TokenBundle, error) {
	if c == nil || c.sdk == nil {
		return coresession.TokenBundle{}, errors.New("bitwarden adapter: client or SDK is nil")
	}
	if tokens.AccountID == "" {
		return coresession.TokenBundle{}, fmt.Errorf("bitwarden adapter: TokenBundle.AccountID must not be empty")
	}

	toLoad := sdk.TokenSet{
		AccountID:    tokens.AccountID,
		AccessToken:  make([]byte, len(tokens.AccessToken)),
		RefreshToken: make([]byte, len(tokens.RefreshToken)),
		TokenType:    tokens.TokenType,
		ExpiresAt:    tokens.ExpiresAt,
	}
	copy(toLoad.AccessToken, tokens.AccessToken)
	copy(toLoad.RefreshToken, tokens.RefreshToken)

	store := newRefreshTokenStore(toLoad)

	opts := []sdk.Option{
		serverIdentityOption(tokens.ServerURL),
		sdk.WithTokenStore(store),
	}
	if c.httpClient != nil {
		opts = append(opts, sdk.WithHTTPClient(c.httpClient))
	}
	refreshClient, err := sdk.NewClient(opts...)
	if err != nil {
		return coresession.TokenBundle{}, fmt.Errorf("bitwarden adapter: creating refresh client: %w", err)
	}
	defer func() {
		_ = refreshClient.Close()
	}()

	result, err := refreshClient.RefreshSession(ctx, tokens.AccountID)
	if err != nil {
		if errors.Is(err, sdk.ErrUnauthorized) {
			return coresession.TokenBundle{}, fmt.Errorf("bitwarden adapter: token refresh unauthorized: %w", coreerrors.ErrUnauthenticated)
		}
		return coresession.TokenBundle{}, err
	}

	updated := coresession.TokenBundle{
		AccountID:    result.Tokens.AccountID,
		Email:        tokens.Email,
		ServerURL:    tokens.ServerURL,
		AccessToken:  make([]byte, len(result.Tokens.AccessToken)),
		RefreshToken: make([]byte, len(result.Tokens.RefreshToken)),
		TokenType:    result.Tokens.TokenType,
		ExpiresAt:    result.Tokens.ExpiresAt,
	}
	copy(updated.AccessToken, result.Tokens.AccessToken)
	copy(updated.RefreshToken, result.Tokens.RefreshToken)

	return updated, nil
}
