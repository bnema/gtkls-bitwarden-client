//go:build linux

package bootid

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
)

// Provider returns the current boot ID from /proc/sys/kernel/random/boot_id.
type Provider struct {
	mu     sync.Mutex
	bootID string
}

// New returns a linux Provider.
func New() *Provider {
	return &Provider{}
}

// BootID reads /proc/sys/kernel/random/boot_id once, trims whitespace, caches
// the successful value, and returns the cached ID on later calls. It returns an
// error when reading fails or the file is empty, and it respects context
// cancellation before starting the read.
func (p *Provider) BootID(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if p == nil {
		return "", errors.New("bootid: provider is nil")
	}

	p.mu.Lock()
	cached := p.bootID
	p.mu.Unlock()
	if cached != "" {
		return cached, nil
	}

	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}

	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("bootid: /proc/sys/kernel/random/boot_id is empty")
	}

	p.mu.Lock()
	if p.bootID == "" {
		p.bootID = id
	}
	cached = p.bootID
	p.mu.Unlock()
	return cached, nil
}
