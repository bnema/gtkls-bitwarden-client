package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreauth "github.com/bnema/gtk4-layershell-bitwarden/internal/core/auth"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	coreerrors "github.com/bnema/gtk4-layershell-bitwarden/internal/core/errors"
	safelog "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	corevault "github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/out"
	"github.com/bnema/zerowrap"
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
	sdk              *sdk.Client
	httpClient       *http.Client // optional; used by RefreshTokenBundle when creating refresh sub-clients
	deviceIdentifier string
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

	return &Client{sdk: sdkClient, deviceIdentifier: effectiveDeviceIdentifier(cfg)}, nil
}

// NewFromSDK wraps an existing SDK client. Useful for tests and future wiring.
func NewFromSDK(client *sdk.Client) *Client {
	return &Client{sdk: client, deviceIdentifier: defaultDeviceIdentifier}
}

// NewFromSDKWithHTTPClient wraps an existing SDK client and sets the HTTP
// client that RefreshTokenBundle uses when creating refresh sub-clients.
func NewFromSDKWithHTTPClient(client *sdk.Client, hc *http.Client) *Client {
	return &Client{sdk: client, httpClient: hc, deviceIdentifier: defaultDeviceIdentifier}
}

func remoteLog(ctx context.Context, operation string) zerowrap.Logger {
	return zerowrap.Logger{Logger: zerowrap.FromCtx(ctx).
		With().
		Str(zerowrap.FieldComponent, "remote.bitwarden").
		Str(zerowrap.FieldOperation, operation).
		Logger()}
}

func logRemoteStart(ctx context.Context, operation string) (zerowrap.Logger, time.Time) {
	started := time.Now()
	log := remoteLog(ctx, operation)
	log.Info().Msg("remote operation started")
	return log, started
}

func logRemoteFinish(log zerowrap.Logger, started time.Time, err error) {
	event := log.Info()
	msg := "remote operation finished"
	if err != nil {
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
		msg = "remote operation failed"
	}
	event.Dur(zerowrap.FieldDuration, time.Since(started)).Msg(msg)
}

func logRemoteFinishCounts(log zerowrap.Logger, started time.Time, err error, itemCount, folderCount int) {
	event := log.Info()
	msg := "remote operation finished"
	if err != nil {
		event = log.Error().Str("error_kind", safelog.SafeErrorKind(err))
		msg = "remote operation failed"
	}
	event.
		Int("item_count", itemCount).
		Int("folder_count", folderCount).
		Dur(zerowrap.FieldDuration, time.Since(started)).
		Msg(msg)
}

func classifySDKError(operation string, err error) error {
	if err == nil {
		return nil
	}

	var kind coreerrors.Kind
	var code, message string
	switch {
	case errors.Is(err, sdk.ErrDecryptionFailed):
		kind = coreerrors.KindCrypto
		code = "decryption_failed"
		message = "vault decryption failed"
	case errors.Is(err, sdk.ErrUnauthorized):
		kind = coreerrors.KindUnauthenticated
		code = "unauthorized"
		message = "authentication required"
	case errors.Is(err, sdk.ErrTwoFactorRequired):
		kind = coreerrors.KindUnauthenticated
		code = "two_factor_required"
		message = "two-factor authentication required"
	case errors.Is(err, sdk.ErrRateLimited):
		kind = coreerrors.KindTemporary
		code = "rate_limited"
		message = "service rate limited"
	case errors.Is(err, sdk.ErrorKindPermissionDenied):
		kind = coreerrors.KindUnauthenticated
		code = "permission_denied"
		message = "permission denied"
	case errors.Is(err, sdk.ErrorKindConflict):
		kind = coreerrors.KindConflict
		code = "conflict"
		message = "vault conflict"
	case errors.Is(err, sdk.ErrorKindNetwork):
		kind = coreerrors.KindNetwork
		code = "network"
		message = "network unavailable"
	case errors.Is(err, sdk.ErrorKindTemporary), errors.Is(err, sdk.ErrorKindUnavailable):
		kind = coreerrors.KindTemporary
		code = "temporary"
		message = "temporary service issue"
	case errors.Is(err, sdk.ErrLocked):
		kind = coreerrors.KindLocked
		code = "locked"
		message = "vault is locked"
	case errors.Is(err, sdk.ErrNotFound):
		kind = coreerrors.KindNotFound
		code = "not_found"
		message = "vault item not found"
	case errors.Is(err, sdk.ErrUnsupported):
		kind = coreerrors.KindUnsupported
		code = "unsupported"
		message = "unsupported vault data"
	default:
		return err
	}

	return &coreerrors.Error{
		Kind:    kind,
		Op:      "remote.bitwarden." + operation,
		Code:    code,
		Message: message,
		Cause:   err,
	}
}

// Login authenticates with master password.
func (c *Client) Login(ctx context.Context, email, password string, rememberedTwoFactorToken []byte) (retErr error) {
	log, started := logRemoteStart(ctx, "login")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return c.sdk.Login(ctx, c.loginOptions(email, password, rememberedTwoFactorToken))
}

// BeginLogin starts login and returns a two-factor challenge when required.
func (c *Client) BeginLogin(ctx context.Context, email, password string, rememberedTwoFactorToken []byte) (challengeResult *coreauth.TwoFactorChallenge, retErr error) {
	log, started := logRemoteStart(ctx, "begin_login")
	defer func() { logRemoteFinish(log, started, retErr) }()

	result, err := c.sdk.BeginLogin(ctx, c.loginOptions(email, password, rememberedTwoFactorToken))
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
func (c *Client) CompleteTwoFactorLogin(ctx context.Context, challenge *coreauth.TwoFactorChallenge, provider coreauth.TwoFactorProvider, code string, remember bool) (retErr error) {
	log, started := logRemoteStart(ctx, "complete_two_factor_login")
	defer func() { logRemoteFinish(log, started, retErr) }()

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
func (c *Client) CompleteTwoFactor(ctx context.Context, _, _ string, _ bool) (retErr error) {
	log, started := logRemoteStart(ctx, "complete_two_factor")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return ErrTwoFactorUnsupported
}

const defaultDeviceIdentifier = "gtk4-layershell-bitwarden"

func effectiveDeviceIdentifier(cfg *coreconfig.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.Device.Identifier) != "" {
		return strings.TrimSpace(cfg.Device.Identifier)
	}
	return defaultDeviceIdentifier
}

func (c *Client) loginOptions(email, password string, rememberedTwoFactorToken []byte) sdk.LoginOptions {
	return sdk.LoginOptions{
		Email:                    email,
		Password:                 password,
		DeviceType:               "LinuxDesktop",
		DeviceIdentifier:         c.deviceIdentifier,
		DeviceName:               "gtk4-layershell-bitwarden",
		RememberedTwoFactorToken: rememberedTwoFactorToken,
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
func (c *Client) Lock(ctx context.Context) (retErr error) {
	log, started := logRemoteStart(ctx, "lock")
	defer func() { logRemoteFinish(log, started, retErr) }()
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
func (c *Client) Revision(ctx context.Context) (revision string, retErr error) {
	log, started := logRemoteStart(ctx, "revision")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return "unknown", nil
}

// Sync refreshes vault state from the server and returns all items, folders,
// and an opaque revision string.
func (c *Client) Sync(ctx context.Context) (items []corevault.Item, folders []corevault.Folder, revision string, retErr error) {
	log, started := logRemoteStart(ctx, "sync")
	defer func() { logRemoteFinishCounts(log, started, retErr, len(items), len(folders)) }()

	if err := c.sdk.Sync(ctx); err != nil {
		return nil, nil, "", classifySDKError("sync", err)
	}

	sdkItems, err := c.sdk.Vault().List(ctx)
	if err != nil {
		return nil, nil, "", classifySDKError("list_items", err)
	}

	sdkFolders, err := c.sdk.Folders().List(ctx)
	if err != nil {
		return nil, nil, "", classifySDKError("list_folders", err)
	}

	items = make([]corevault.Item, 0, len(sdkItems))
	for _, si := range sdkItems {
		ci, err := toCoreItem(si)
		if err != nil {
			return nil, nil, "", classifySDKError("map_item", err)
		}
		items = append(items, ci)
	}

	folders = make([]corevault.Folder, len(sdkFolders))
	for i, sf := range sdkFolders {
		folders[i] = toCoreFolder(sf)
	}

	return items, folders, "unknown", nil
}

// Create creates a new vault item.
func (c *Client) Create(ctx context.Context, item corevault.Item) (result corevault.Item, retErr error) {
	log, started := logRemoteStart(ctx, "create")
	defer func() { logRemoteFinish(log, started, retErr) }()

	created, err := c.sdk.Vault().Create(ctx, toSDKItem(item))
	if err != nil {
		return corevault.Item{}, err
	}
	return toCoreItem(created)
}

// Update updates an existing vault item by ID.
func (c *Client) Update(ctx context.Context, id string, item corevault.Item) (result corevault.Item, retErr error) {
	log, started := logRemoteStart(ctx, "update")
	defer func() { logRemoteFinish(log, started, retErr) }()

	updated, err := c.sdk.Vault().Update(ctx, sdk.ItemID(id), toSDKItem(item))
	if err != nil {
		return corevault.Item{}, err
	}
	return toCoreItem(updated)
}

// Trash soft-deletes (trashes) a vault item.
func (c *Client) Trash(ctx context.Context, id string) (retErr error) {
	log, started := logRemoteStart(ctx, "trash")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return c.sdk.Vault().Trash(ctx, sdk.ItemID(id))
}

// Restore restores a trashed vault item.
func (c *Client) Restore(ctx context.Context, id string) (result corevault.Item, retErr error) {
	log, started := logRemoteStart(ctx, "restore")
	defer func() { logRemoteFinish(log, started, retErr) }()

	restored, err := c.sdk.Vault().Restore(ctx, sdk.ItemID(id))
	if err != nil {
		return corevault.Item{}, err
	}
	return toCoreItem(restored)
}

// Delete permanently deletes a vault item.
func (c *Client) Delete(ctx context.Context, id string) (retErr error) {
	log, started := logRemoteStart(ctx, "delete")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return c.sdk.Vault().Delete(ctx, sdk.ItemID(id))
}

// ListAttachments returns ErrAttachmentsNotSupported because the public SDK
// Item type does not expose an Attachments field. The SDK can
// download/upload/delete individual attachments by known ID but cannot
// enumerate them at the item level through the public API surface.
func (c *Client) ListAttachments(ctx context.Context, _ string) (attachments []corevault.Attachment, retErr error) {
	log, started := logRemoteStart(ctx, "list_attachments")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return nil, ErrAttachmentsNotSupported
}

// DownloadAttachment downloads and decrypts an attachment to dst.
func (c *Client) DownloadAttachment(ctx context.Context, itemID, attachmentID string, dst io.Writer) (retErr error) {
	log, started := logRemoteStart(ctx, "download_attachment")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return c.sdk.Attachments().Download(ctx, itemID, attachmentID, dst)
}

// UploadAttachment encrypts and uploads an attachment from src.
func (c *Client) UploadAttachment(ctx context.Context, itemID, fileName string, size int64, src io.Reader) (attachment corevault.Attachment, retErr error) {
	log, started := logRemoteStart(ctx, "upload_attachment")
	defer func() { logRemoteFinish(log, started, retErr) }()

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
func (c *Client) DeleteAttachment(ctx context.Context, itemID, attachmentID string) (retErr error) {
	log, started := logRemoteStart(ctx, "delete_attachment")
	defer func() { logRemoteFinish(log, started, retErr) }()
	return c.sdk.Attachments().Delete(ctx, itemID, attachmentID)
}

// ExportSession returns the current unlocked session material and tokens.
func (c *Client) ExportSession(ctx context.Context) (materialResult coresession.UnlockMaterial, tokenResult coresession.TokenBundle, retErr error) {
	log, started := logRemoteStart(ctx, "export_session")
	defer func() { logRemoteFinish(log, started, retErr) }()

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
		AccountID:                sdkMaterial.Tokens.AccountID,
		AccessToken:              make([]byte, len(sdkMaterial.Tokens.AccessToken)),
		RefreshToken:             make([]byte, len(sdkMaterial.Tokens.RefreshToken)),
		RememberedTwoFactorToken: make([]byte, len(sdkMaterial.Tokens.RememberedTwoFactorToken)),
		TokenType:                sdkMaterial.Tokens.TokenType,
		ExpiresAt:                sdkMaterial.Tokens.ExpiresAt,
	}
	copy(tokens.AccessToken, sdkMaterial.Tokens.AccessToken)
	copy(tokens.RefreshToken, sdkMaterial.Tokens.RefreshToken)
	copy(tokens.RememberedTwoFactorToken, sdkMaterial.Tokens.RememberedTwoFactorToken)

	return material, tokens, nil
}

// RestoreSession imports session material and tokens, unlocking the client.
func (c *Client) RestoreSession(ctx context.Context, material coresession.UnlockMaterial, tokens coresession.TokenBundle) (retErr error) {
	log, started := logRemoteStart(ctx, "restore_session")
	defer func() { logRemoteFinish(log, started, retErr) }()

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
			AccountID:                tokens.AccountID,
			AccessToken:              make([]byte, len(tokens.AccessToken)),
			RefreshToken:             make([]byte, len(tokens.RefreshToken)),
			RememberedTwoFactorToken: make([]byte, len(tokens.RememberedTwoFactorToken)),
			TokenType:                tokens.TokenType,
			ExpiresAt:                tokens.ExpiresAt,
		},
	}
	copy(sdkMaterial.UserKey, material.UserKey)
	copy(sdkMaterial.Tokens.AccessToken, tokens.AccessToken)
	copy(sdkMaterial.Tokens.RefreshToken, tokens.RefreshToken)
	copy(sdkMaterial.Tokens.RememberedTwoFactorToken, tokens.RememberedTwoFactorToken)
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
func (c *Client) RefreshTokenBundle(ctx context.Context, tokens coresession.TokenBundle) (bundle coresession.TokenBundle, retErr error) {
	log, started := logRemoteStart(ctx, "refresh_token_bundle")
	defer func() { logRemoteFinish(log, started, retErr) }()

	if c == nil || c.sdk == nil {
		return coresession.TokenBundle{}, errors.New("bitwarden adapter: client or SDK is nil")
	}
	if tokens.AccountID == "" {
		return coresession.TokenBundle{}, fmt.Errorf("bitwarden adapter: TokenBundle.AccountID must not be empty")
	}

	toLoad := sdk.TokenSet{
		AccountID:                tokens.AccountID,
		AccessToken:              make([]byte, len(tokens.AccessToken)),
		RefreshToken:             make([]byte, len(tokens.RefreshToken)),
		RememberedTwoFactorToken: make([]byte, len(tokens.RememberedTwoFactorToken)),
		TokenType:                tokens.TokenType,
		ExpiresAt:                tokens.ExpiresAt,
	}
	copy(toLoad.AccessToken, tokens.AccessToken)
	copy(toLoad.RefreshToken, tokens.RefreshToken)
	copy(toLoad.RememberedTwoFactorToken, tokens.RememberedTwoFactorToken)

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
		AccountID:                result.Tokens.AccountID,
		Email:                    tokens.Email,
		ServerURL:                tokens.ServerURL,
		AccessToken:              make([]byte, len(result.Tokens.AccessToken)),
		RefreshToken:             make([]byte, len(result.Tokens.RefreshToken)),
		RememberedTwoFactorToken: make([]byte, len(result.Tokens.RememberedTwoFactorToken)),
		TokenType:                result.Tokens.TokenType,
		ExpiresAt:                result.Tokens.ExpiresAt,
	}
	copy(updated.AccessToken, result.Tokens.AccessToken)
	copy(updated.RefreshToken, result.Tokens.RefreshToken)
	copy(updated.RememberedTwoFactorToken, result.Tokens.RememberedTwoFactorToken)

	return updated, nil
}
