package clipboard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type WaylandForegroundProvider struct {
	lookPath func(string) (string, error)
}

func NewWaylandForegroundProvider() WaylandForegroundProvider {
	return WaylandForegroundProvider{lookPath: exec.LookPath}
}

func (p WaylandForegroundProvider) Serve(ctx context.Context, data []byte, ttl time.Duration) error {
	if ttl < 0 {
		return fmt.Errorf("clipboard: ttl must be non-negative")
	}
	path, err := p.findWLCopy()
	if err != nil {
		return err
	}

	args := []string{"--foreground", "--type", "text/plain"}
	runCtx := ctx
	if ttl > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, ttl)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, path, args...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if ttl > 0 && runCtx.Err() == context.DeadlineExceeded {
			return nil
		}
		return fmt.Errorf("clipboard: wl-copy foreground provider: %w", err)
	}
	return nil
}

func (p WaylandForegroundProvider) findWLCopy() (string, error) {
	lookPath := p.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath("wl-copy")
	if err != nil {
		return "", fmt.Errorf("clipboard: wl-copy not found: %w", err)
	}
	return path, nil
}
