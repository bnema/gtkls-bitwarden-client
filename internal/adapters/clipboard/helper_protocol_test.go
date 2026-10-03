package clipboard

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHelperRequestRoundTrip(t *testing.T) {
	for _, ttl := range []time.Duration{0, 45 * time.Second, 1500 * time.Millisecond} {
		req := HelperRequest{Secret: []byte("secret-password\nwith newline"), TTL: ttl}

		args := req.Args()
		require.Equal(t, HelperCommandName, args[0])
		for _, arg := range args {
			require.NotContains(t, arg, "secret")
		}

		got, err := DecodeHelperRequest(args[1:], req.Stdin())

		require.NoError(t, err)
		require.Equal(t, req.Secret, got.Secret)
		require.Equal(t, ttl, got.TTL)
	}
}

func TestDecodeHelperRequestRejectsNegativeTTL(t *testing.T) {
	_, err := DecodeHelperRequest([]string{"--ttl", "-1s"}, strings.NewReader("secret"))

	require.Error(t, err)
	require.Contains(t, err.Error(), "ttl must be non-negative")
}

func TestDecodeHelperRequestRejectsUnexpectedArguments(t *testing.T) {
	_, err := DecodeHelperRequest([]string{"--ttl", "1s", "secret"}, strings.NewReader("x"))

	require.Error(t, err)
}

func TestDecodeHelperRequestRejectsOversizedInput(t *testing.T) {
	input := bytes.Repeat([]byte("x"), maxSecretBytes+1)

	req, err := DecodeHelperRequest(nil, bytes.NewReader(input))

	require.Error(t, err)
	require.Nil(t, req.Secret)
	require.Contains(t, err.Error(), "stdin exceeds")
}

func TestRunHelperReadsSecretFromStdinOnly(t *testing.T) {
	var got []byte
	var gotTTL time.Duration
	provider := func(_ context.Context, secret []byte, ttl time.Duration) error {
		got = append([]byte(nil), secret...)
		gotTTL = ttl
		return nil
	}

	err := RunHelper(context.Background(), []string{"--ttl", "3s"}, strings.NewReader("secret-password"), provider)

	require.NoError(t, err)
	require.Equal(t, []byte("secret-password"), got)
	require.Equal(t, 3*time.Second, gotTTL)
}

func TestRunHelperZeroesSecretAfterProvider(t *testing.T) {
	var held []byte
	provider := func(_ context.Context, secret []byte, _ time.Duration) error {
		held = secret
		return nil
	}

	require.NoError(t, RunHelper(context.Background(), nil, strings.NewReader("secret"), provider))

	require.Equal(t, make([]byte, len("secret")), held)
}

func TestRunHelperRejectsNegativeTTL(t *testing.T) {
	err := RunHelper(context.Background(), []string{"--ttl=-1s"}, strings.NewReader("secret"), nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "ttl must be non-negative")
}
