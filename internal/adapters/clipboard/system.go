package clipboard

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SystemWriter writes clipboard contents through platform clipboard commands.
// On Wayland it prefers wl-copy, matching the command-line clipboard path used
// by related tools. X11 fallbacks are kept for non-Wayland sessions.
type SystemWriter struct {
	lookPath func(string) (string, error)
	getenv   func(string) string
}

func NewSystemWriter() SystemWriter {
	return SystemWriter{
		lookPath: exec.LookPath,
		getenv:   os.Getenv,
	}
}

func (w SystemWriter) WriteClipboard(ctx context.Context, text string) error {
	command, ok := w.selectCommand()
	if !ok {
		return fmt.Errorf("no supported clipboard tool found; install wl-copy for Wayland or xclip/xsel for X11")
	}
	if err := runCommand(ctx, command, text); err != nil {
		return fmt.Errorf("copy to clipboard with %s: %w", command.name, err)
	}
	return nil
}

type clipboardCommand struct {
	name string
	args []string
}

func (w SystemWriter) selectCommand() (clipboardCommand, bool) {
	if w.getenv == nil {
		w.getenv = os.Getenv
	}
	if w.getenv("WAYLAND_DISPLAY") != "" {
		if path, ok := w.findCommand("wl-copy"); ok {
			return clipboardCommand{name: path, args: []string{"--type", "text/plain"}}, true
		}
	}
	if w.getenv("DISPLAY") != "" || w.getenv("WAYLAND_DISPLAY") != "" {
		if path, ok := w.findCommand("xclip"); ok {
			return clipboardCommand{name: path, args: []string{"-selection", "clipboard"}}, true
		}
		if path, ok := w.findCommand("xsel"); ok {
			return clipboardCommand{name: path, args: []string{"--clipboard", "--input"}}, true
		}
	}
	return clipboardCommand{}, false
}

func (w SystemWriter) findCommand(name string) (string, bool) {
	lookPath := w.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	path, err := lookPath(name)
	return path, err == nil
}

func runCommand(ctx context.Context, command clipboardCommand, input string) error {
	cmd := exec.CommandContext(ctx, command.name, command.args...)
	cmd.Stdin = bytes.NewBufferString(input)
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
