//go:build linux

package bootid

import (
	"context"
	"errors"
	"os"
	"strings"
)

// Provider returns the current boot ID from /proc/sys/kernel/random/boot_id.
type Provider struct{}

// New returns a linux Provider.
func New() Provider {
	return Provider{}
}

// BootID reads /proc/sys/kernel/random/boot_id, trims whitespace and returns
// the boot ID string.  It returns an error when reading fails or the file is
// empty, and it respects context cancellation before starting the read.
func (Provider) BootID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}

	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("bootid: /proc/sys/kernel/random/boot_id is empty")
	}
	return id, nil
}
