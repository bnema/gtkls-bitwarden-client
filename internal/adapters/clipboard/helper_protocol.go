package clipboard

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/secretmem"
)

const (
	// HelperCommandName is the hidden subcommand the helper process runs.
	HelperCommandName = "__clipboard-helper"

	helperTTLFlag = "ttl"

	// maxSecretBytes bounds the secret accepted on helper stdin.
	maxSecretBytes = 64 * 1024
)

// HelperProvider owns the clipboard selection for the helper process. It must
// block while the selection is being served and return when ttl expires (or
// when the backend stops serving if ttl is 0).
type HelperProvider func(ctx context.Context, secret []byte, ttl time.Duration) error

// HelperRequest is the parent->helper message. TTL travels in argv (not
// secret); Secret travels on stdin only, never in argv or env.
type HelperRequest struct {
	Secret []byte
	TTL    time.Duration
}

func (r HelperRequest) validate() error {
	if r.TTL < 0 {
		return errors.New("clipboard: ttl must be non-negative")
	}
	return nil
}

// Args returns the helper argv (excluding the executable path): the command
// name followed by non-secret flags.
func (r HelperRequest) Args() []string {
	return []string{HelperCommandName, "--" + helperTTLFlag, r.TTL.String()}
}

// Stdin returns the reader carrying the secret. It does not copy Secret.
func (r HelperRequest) Stdin() io.Reader {
	return bytes.NewReader(r.Secret)
}

// DecodeHelperRequest is the inverse of Args/Stdin. args are the arguments
// following HelperCommandName. The caller owns the returned Secret and should
// zero it when done.
func DecodeHelperRequest(args []string, stdin io.Reader) (HelperRequest, error) {
	var req HelperRequest
	fs := flag.NewFlagSet(HelperCommandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.DurationVar(&req.TTL, helperTTLFlag, 0, "clipboard lifetime before helper exits")
	if err := fs.Parse(args); err != nil {
		return HelperRequest{}, fmt.Errorf("clipboard helper: %w", err)
	}
	if fs.NArg() > 0 {
		return HelperRequest{}, fmt.Errorf("clipboard helper: unexpected arguments")
	}
	if req.TTL < 0 {
		return HelperRequest{}, errors.New("clipboard helper: ttl must be non-negative")
	}

	data, err := io.ReadAll(io.LimitReader(stdin, maxSecretBytes+1))
	if err != nil {
		clear(data)
		return HelperRequest{}, fmt.Errorf("clipboard helper: read stdin: %w", err)
	}
	if len(data) > maxSecretBytes {
		clear(data)
		return HelperRequest{}, fmt.Errorf("clipboard helper: stdin exceeds %d bytes", maxSecretBytes)
	}
	req.Secret = data
	return req, nil
}

// RunHelper is the helper-process side of the protocol: it decodes the request
// and serves the secret through provider (the Wayland foreground provider when
// nil). The secret is zeroed before returning.
func RunHelper(ctx context.Context, args []string, stdin io.Reader, provider HelperProvider) error {
	var err error
	secretmem.Do(func() {
		var req HelperRequest
		req, err = DecodeHelperRequest(args, stdin)
		if err != nil {
			return
		}
		defer clear(req.Secret)
		if provider == nil {
			provider = newSystemTools().serveForeground
		}
		err = provider(ctx, req.Secret, req.TTL)
	})
	return err
}
