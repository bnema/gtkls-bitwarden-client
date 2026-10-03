// Package clipboard implements out.Clipboard. It owns the whole clipboard
// policy: copies are handed to a detached helper process of this same binary,
// which keeps the clipboard selection alive after the overlay exits and
// releases it when the TTL expires. This package defines both sides of the
// parent/helper protocol (see helper_protocol.go).
package clipboard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

// ErrClipboardUnavailable reports that no clipboard backend is available.
var ErrClipboardUnavailable = errors.New("clipboard: no clipboard backend available")

// HelperClipboard implements out.Clipboard by delegating to a helper process.
// Clipboard contents are sent to the helper on stdin only; argv/env carry
// non-secret process configuration.
type HelperClipboard struct {
	executable func() (string, error)
	runner     helperRunner
	tools      systemTools
}

// NewHelperClipboard returns a clipboard backed by a re-executed helper process.
func NewHelperClipboard() *HelperClipboard {
	return &HelperClipboard{
		executable: os.Executable,
		runner:     processHelperRunner{},
		tools:      newSystemTools(),
	}
}

// Set copies text through the helper process, which serves it for ttl (0 means
// until another client takes the selection). The input string is owned by the
// caller and cannot be zeroed here; this method only zeroes the temporary byte
// copy used to feed helper stdin.
func (c *HelperClipboard) Set(ctx context.Context, text string, ttl time.Duration) error {
	req := HelperRequest{Secret: []byte(text), TTL: ttl}
	defer clear(req.Secret)
	if err := req.validate(); err != nil {
		return err
	}
	executable := c.executable
	if executable == nil {
		executable = os.Executable
	}
	path, err := executable()
	if err != nil {
		return fmt.Errorf("clipboard: resolve helper executable: %w", err)
	}
	runner := c.runner
	if runner == nil {
		runner = processHelperRunner{}
	}
	return runner.Run(ctx, helperCommand{name: path, args: req.Args()}, req.Stdin())
}

// Clear empties the system clipboard.
func (c *HelperClipboard) Clear(ctx context.Context) error {
	tools := c.tools
	if tools.lookPath == nil && tools.getenv == nil {
		tools = newSystemTools()
	}
	return tools.write(ctx, nil)
}

var _ out.Clipboard = (*HelperClipboard)(nil)
