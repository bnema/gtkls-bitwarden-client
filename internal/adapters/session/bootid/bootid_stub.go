//go:build !linux

package bootid

import "context"

// Provider returns a hard-coded stub boot ID for non-Linux platforms.
type Provider struct{}

// New returns a non-linux Provider.
func New() *Provider {
	return &Provider{}
}

const stubBootID = "non-linux-test-boot"

// BootID returns "non-linux-test-boot" unless the context is cancelled, in
// which case it returns the context error.
func (*Provider) BootID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return stubBootID, nil
}
