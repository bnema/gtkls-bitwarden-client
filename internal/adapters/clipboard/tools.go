package clipboard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// systemTools drives platform clipboard commands. On Wayland it prefers
// wl-copy; X11 fallbacks are kept for non-Wayland sessions.
type systemTools struct {
	lookPath func(string) (string, error)
	getenv   func(string) string
}

func newSystemTools() systemTools {
	return systemTools{lookPath: exec.LookPath, getenv: os.Getenv}
}

type clipboardCommand struct {
	name string
	args []string
}

// write replaces the clipboard contents using wl-copy's native background
// provider (or xclip/xsel). Empty data clears the selection.
func (t systemTools) write(ctx context.Context, data []byte) error {
	command, ok := t.selectCommand()
	if !ok {
		return fmt.Errorf("no supported clipboard tool found; install wl-copy for Wayland or xclip/xsel for X11")
	}
	if err := runCommand(ctx, command, data); err != nil {
		return fmt.Errorf("copy to clipboard with %s: %w", command.name, err)
	}
	return nil
}

func (t systemTools) selectCommand() (clipboardCommand, bool) {
	getenv := t.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if getenv("WAYLAND_DISPLAY") != "" {
		if path, ok := t.findCommand("wl-copy"); ok {
			return clipboardCommand{name: path, args: []string{"--type", "text/plain"}}, true
		}
	}
	if getenv("DISPLAY") != "" || getenv("WAYLAND_DISPLAY") != "" {
		if path, ok := t.findCommand("xclip"); ok {
			return clipboardCommand{name: path, args: []string{"-selection", "clipboard"}}, true
		}
		if path, ok := t.findCommand("xsel"); ok {
			return clipboardCommand{name: path, args: []string{"--clipboard", "--input"}}, true
		}
	}
	return clipboardCommand{}, false
}

func (t systemTools) findCommand(name string) (string, bool) {
	lookPath := t.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath(name)
	return path, err == nil
}

func runCommand(ctx context.Context, command clipboardCommand, input []byte) error {
	cmd := exec.CommandContext(ctx, command.name, command.args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

// serveForeground runs wl-copy in the foreground so the calling (helper)
// process owns the selection. It returns nil when ttl expires.
func (t systemTools) serveForeground(ctx context.Context, data []byte, ttl time.Duration) error {
	if ttl < 0 {
		return fmt.Errorf("clipboard: ttl must be non-negative")
	}
	lookPath := t.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath("wl-copy")
	if err != nil {
		return fmt.Errorf("clipboard: wl-copy not found: %w", err)
	}

	runCtx := ctx
	if ttl > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, ttl)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, path, "--foreground", "--type", "text/plain")
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
