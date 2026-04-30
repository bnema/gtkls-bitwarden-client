package bitwarden

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreconfig "github.com/bnema/gtk4-layershell-bitwarden/internal/core/config"
	coresession "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientRejectsInvalidSelfHostedURL(t *testing.T) {
	// A self-hosted config with a non-https URL should be rejected by the SDK.
	cfg := &coreconfig.Config{
		Bitwarden: coreconfig.Bitwarden{
			Email:     "test@example.com",
			Region:    coreconfig.RegionSelfHosted,
			ServerURL: "http://bad",
		},
	}
	_, err := NewClient(cfg)
	require.Error(t, err, "expected error for invalid self-hosted URL")
}

func TestNewClientDefaultUSNoNetwork(t *testing.T) {
	// NewClient with default US region should construct without network calls.
	cfg := &coreconfig.Config{
		Bitwarden: coreconfig.Bitwarden{
			Email:  "test@example.com",
			Region: coreconfig.RegionUS,
		},
	}
	client, err := NewClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	// White-box: verify the underlying SDK client is non-nil and locked.
	// We access client.sdk directly because IsLocked has no public
	// equivalent on the adapter — the adapter's Lock() method delegates
	// to the same SDK method and returns nil, but we cannot assert on
	// error alone to prove the SDK state changed.
	assert.True(t, client.sdk.IsLocked())
}

func TestRevisionReturnsOpaqueUnknown(t *testing.T) {
	// Use NewFromSDK with a bare SDK client (no network required).
	sdkClient, err := sdk.NewClient()
	require.NoError(t, err)
	adapter := NewFromSDK(sdkClient)

	rev, err := adapter.Revision(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "unknown", rev)
}

func TestNewFromSDK(t *testing.T) {
	sdkClient, err := sdk.NewClient()
	require.NoError(t, err)
	adapter := NewFromSDK(sdkClient)
	require.NotNil(t, adapter)
	assert.Same(t, sdkClient, adapter.sdk)
}

func TestLockReturnsNil(t *testing.T) {
	sdkClient, err := sdk.NewClient()
	require.NoError(t, err)
	adapter := NewFromSDK(sdkClient)

	err = adapter.Lock(context.Background())
	require.NoError(t, err)
	assert.True(t, sdkClient.IsLocked())
}

// ---------------------------------------------------------------------------
// Session export / restore round-trip
// ---------------------------------------------------------------------------

func TestRemoteExportRestoreSessionRoundTrip(t *testing.T) {
	// Create an SDK client, unlock it via the SDK's own RestoreSession,
	// then export via the adapter, re-import via the adapter, and verify.
	sdkClient1, err := sdk.NewClient()
	require.NoError(t, err)
	defer func() { _ = sdkClient1.Close() }()

	require.True(t, sdkClient1.IsLocked())

	sdkClient1UserKey := []byte("roundtrip-user-key")
	sdkClient1Access := []byte("roundtrip-access")
	sdkClient1Refresh := []byte("roundtrip-refresh")
	sdkClient1Expires := time.Now().Add(time.Hour)

	err = sdkClient1.RestoreSession(context.Background(), sdk.SessionMaterial{
		AccountID: "acct-roundtrip",
		UserKey:   sdkClient1UserKey,
		Tokens: sdk.TokenSet{
			AccountID:    "acct-roundtrip",
			AccessToken:  sdkClient1Access,
			RefreshToken: sdkClient1Refresh,
			TokenType:    "Bearer",
			ExpiresAt:    sdkClient1Expires,
		},
	})
	require.NoError(t, err)
	require.False(t, sdkClient1.IsLocked())

	// Export through the adapter.
	adapter1 := NewFromSDK(sdkClient1)
	material, tokens, err := adapter1.ExportSession(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, material.UserKey)
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	require.Equal(t, "acct-roundtrip", tokens.AccountID)
	require.Equal(t, "Bearer", tokens.TokenType)

	// Verify exported data matches what we put in (modulo copy semantics).
	assert.Equal(t, sdkClient1UserKey, material.UserKey)
	assert.Equal(t, sdkClient1Access, tokens.AccessToken)
	assert.Equal(t, sdkClient1Refresh, tokens.RefreshToken)

	// Restore into a fresh SDK client via the adapter.
	sdkClient2, err := sdk.NewClient()
	require.NoError(t, err)
	defer func() { _ = sdkClient2.Close() }()
	require.True(t, sdkClient2.IsLocked())

	adapter2 := NewFromSDK(sdkClient2)
	err = adapter2.RestoreSession(context.Background(), material, tokens)
	require.NoError(t, err)
	require.False(t, sdkClient2.IsLocked())

	// Re-export from the restored client.
	material2, tokens2, err := adapter2.ExportSession(context.Background())
	require.NoError(t, err)
	assert.Equal(t, material.UserKey, material2.UserKey)
	assert.Equal(t, tokens.AccountID, tokens2.AccountID)
	assert.Equal(t, tokens.TokenType, tokens2.TokenType)
}

func TestRemoteSessionMethodsNilSDKReturnError(t *testing.T) {
	t.Run("ExportSession nil sdk", func(t *testing.T) {
		var c *Client // nil
		_, _, err := c.ExportSession(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("ExportSession nil sdk field", func(t *testing.T) {
		c := &Client{sdk: nil}
		_, _, err := c.ExportSession(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("RestoreSession nil sdk", func(t *testing.T) {
		var c *Client
		err := c.RestoreSession(context.Background(), coresession.UnlockMaterial{}, coresession.TokenBundle{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("RestoreSession nil sdk field", func(t *testing.T) {
		c := &Client{sdk: nil}
		err := c.RestoreSession(context.Background(), coresession.UnlockMaterial{}, coresession.TokenBundle{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("RefreshTokenBundle nil sdk", func(t *testing.T) {
		var c *Client
		_, err := c.RefreshTokenBundle(context.Background(), coresession.TokenBundle{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})

	t.Run("RefreshTokenBundle nil sdk field", func(t *testing.T) {
		c := &Client{sdk: nil}
		_, err := c.RefreshTokenBundle(context.Background(), coresession.TokenBundle{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "nil")
	})
}

func TestRestoreSessionEmptyAccountIDReturnsError(t *testing.T) {
	sdkClient, err := sdk.NewClient()
	require.NoError(t, err)
	defer func() { _ = sdkClient.Close() }()

	adapter := NewFromSDK(sdkClient)
	err = adapter.RestoreSession(context.Background(),
		coresession.UnlockMaterial{UserKey: []byte("key")},
		coresession.TokenBundle{AccountID: ""},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AccountID must not be empty")
}

// ---------------------------------------------------------------------------
// RefreshTokenBundle tests
// ---------------------------------------------------------------------------

func TestClassifyServerIdentity(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantRegion     sdk.Region
		wantSelfHosted string
	}{
		{name: "empty", input: "", wantRegion: sdk.RegionUS, wantSelfHosted: ""},
		{name: "us cloud", input: "https://vault.bitwarden.com", wantRegion: sdk.RegionUS, wantSelfHosted: ""},
		{name: "us cloud trailing slash", input: "https://vault.bitwarden.com/", wantRegion: sdk.RegionUS, wantSelfHosted: ""},
		{name: "eu cloud", input: "https://vault.bitwarden.eu", wantRegion: sdk.RegionEU, wantSelfHosted: ""},
		{name: "eu cloud trailing slash", input: "https://vault.bitwarden.eu/", wantRegion: sdk.RegionEU, wantSelfHosted: ""},
		{name: "self-hosted", input: "https://bw.example.com", wantRegion: "", wantSelfHosted: "https://bw.example.com"},
		{name: "self-hosted with path", input: "https://bw.example.com/bitwarden", wantRegion: "", wantSelfHosted: "https://bw.example.com/bitwarden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, selfHosted := classifyServerIdentity(tt.input)
			assert.Equal(t, tt.wantRegion, region)
			assert.Equal(t, tt.wantSelfHosted, selfHosted)
		})
	}
}

// tokenRefreshHandler returns an httptest handler that serves a valid
// Bitwarden /connect/token JSON response with the given access/refresh tokens.
func tokenRefreshHandler(newAccess, newRefresh, accountID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  newAccess,
			"refresh_token": newRefresh,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"AccountId":     accountID,
		})
	}
}

// identityProxyTransport rewrites HTTPS URLs to the target httptest server,
// recording the host of each request for inspection.
type identityProxyTransport struct {
	target      string
	inner       http.RoundTripper
	recordHosts []string
	mu          sync.Mutex
}

func (rt *identityProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.recordHosts = append(rt.recordHosts, req.URL.Host)
	rt.mu.Unlock()

	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = "http"
	cloned.URL.Host = rt.target
	cloned.Host = ""
	return rt.inner.RoundTrip(cloned)
}

func newIdentityProxyClient(ts *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &identityProxyTransport{
			target: ts.Listener.Addr().String(),
			inner:  http.DefaultTransport,
		},
	}
}

func TestRefreshTokenBundlePreservesMetadataAndUpdatesTokens(t *testing.T) {
	// Use httptest as a self-hosted identity proxy.
	mux := http.NewServeMux()
	mux.HandleFunc("/connect/token", tokenRefreshHandler("new-access", "new-refresh", "account-meta"))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	proxyClient := newIdentityProxyClient(ts)

	// Adapter needs a non-nil SDK client for nil guard; the refresh sub-client
	// will get the proxy HTTP client so it can reach the httptest server.
	bareSDK, err := sdk.NewClient()
	require.NoError(t, err)
	defer func() { _ = bareSDK.Close() }()

	adapter := NewFromSDKWithHTTPClient(bareSDK, proxyClient)

	input := coresession.TokenBundle{
		AccountID:    "account-meta",
		Email:        "meta@example.com",
		ServerURL:    "https://vault.bitwarden.com",
		AccessToken:  []byte("old-access"),
		RefreshToken: []byte("old-refresh"),
		TokenType:    "Bearer",
		ExpiresAt:    time.Now(),
	}

	result, err := adapter.RefreshTokenBundle(context.Background(), input)
	require.NoError(t, err)

	// Tokens should be updated.
	assert.Equal(t, []byte("new-access"), result.AccessToken)
	assert.Equal(t, []byte("new-refresh"), result.RefreshToken)

	// Metadata preserved.
	assert.Equal(t, "meta@example.com", result.Email)
	assert.Equal(t, "https://vault.bitwarden.com", result.ServerURL)
	assert.Equal(t, "account-meta", result.AccountID)
	assert.Equal(t, "Bearer", result.TokenType)
	// ExpiresAt should be in the future (approx 1h from now).
	assert.True(t, result.ExpiresAt.After(time.Now()))
}

func TestRefreshTokenBundleEmptyAccountIDReturnsError(t *testing.T) {
	sdkClient, err := sdk.NewClient()
	require.NoError(t, err)
	defer func() { _ = sdkClient.Close() }()

	adapter := NewFromSDK(sdkClient)
	_, err = adapter.RefreshTokenBundle(context.Background(), coresession.TokenBundle{
		AccountID: "",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "AccountID must not be empty")
}

func TestRefreshTokenBundleUsesEUAndSelfHostedIdentity(t *testing.T) {
	// Set up httptest server that handles both /connect/token (cloud path)
	// and /identity/connect/token (self-hosted path).
	mux := http.NewServeMux()
	h := tokenRefreshHandler("at", "rt", "acct-eu-t")
	mux.HandleFunc("/connect/token", h)
	mux.HandleFunc("/identity/connect/token", h)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	t.Run("EU identity endpoint", func(t *testing.T) {
		proxyClient := newIdentityProxyClient(ts)

		bareSDK, err := sdk.NewClient()
		require.NoError(t, err)
		defer func() { _ = bareSDK.Close() }()

		adapter := NewFromSDKWithHTTPClient(bareSDK, proxyClient)
		input := coresession.TokenBundle{
			AccountID:    "acct-eu-t",
			AccessToken:  []byte("old"),
			RefreshToken: []byte("old"),
			ServerURL:    "https://vault.bitwarden.eu",
		}

		_, err = adapter.RefreshTokenBundle(context.Background(), input)
		require.NoError(t, err)

		transport, ok := proxyClient.Transport.(*identityProxyTransport)
		require.True(t, ok)
		require.NotEmpty(t, transport.recordHosts)
		assert.Equal(t, "identity.bitwarden.eu", transport.recordHosts[0])
	})

	t.Run("self-hosted identity endpoint", func(t *testing.T) {
		proxyClient := newIdentityProxyClient(ts)

		bareSDK, err := sdk.NewClient()
		require.NoError(t, err)
		defer func() { _ = bareSDK.Close() }()

		adapter := NewFromSDKWithHTTPClient(bareSDK, proxyClient)
		input := coresession.TokenBundle{
			AccountID:    "acct-sh-t",
			AccessToken:  []byte("old"),
			RefreshToken: []byte("old"),
			ServerURL:    "https://selfhosted.example.com",
		}

		_, err = adapter.RefreshTokenBundle(context.Background(), input)
		require.NoError(t, err)

		transport, ok := proxyClient.Transport.(*identityProxyTransport)
		require.True(t, ok)
		require.NotEmpty(t, transport.recordHosts)
		assert.Equal(t, "selfhosted.example.com", transport.recordHosts[0])
	})

	t.Run("US identity endpoint (default)", func(t *testing.T) {
		proxyClient := newIdentityProxyClient(ts)

		bareSDK, err := sdk.NewClient()
		require.NoError(t, err)
		defer func() { _ = bareSDK.Close() }()

		adapter := NewFromSDKWithHTTPClient(bareSDK, proxyClient)
		input := coresession.TokenBundle{
			AccountID:    "acct-us-t",
			AccessToken:  []byte("old"),
			RefreshToken: []byte("old"),
			ServerURL:    "https://vault.bitwarden.com",
		}

		_, err = adapter.RefreshTokenBundle(context.Background(), input)
		require.NoError(t, err)

		transport, ok := proxyClient.Transport.(*identityProxyTransport)
		require.True(t, ok)
		require.NotEmpty(t, transport.recordHosts)
		assert.Equal(t, "identity.bitwarden.com", transport.recordHosts[0])
	})
}
