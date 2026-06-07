package clipboard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/clipboard/helpercmd"
	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

type helperCommand struct {
	name string
	args []string
}

type helperRunner interface {
	Run(ctx context.Context, cmd helperCommand, stdin io.Reader) error
}

// HelperClipboard starts a detached helper process that owns the clipboard
// provider after the overlay exits. Clipboard contents are sent to the helper
// on stdin only; argv/env are limited to non-secret process configuration.
type HelperClipboard struct {
	executable func() (string, error)
	runner     helperRunner
}

func NewHelperClipboard() *HelperClipboard {
	return &HelperClipboard{
		executable: os.Executable,
		runner:     processHelperRunner{},
	}
}

// Set copies text through the helper process. The input string is owned by the
// caller and cannot be zeroed here; this method only zeroes the temporary byte
// copy used to feed helper stdin.
func (c *HelperClipboard) Set(ctx context.Context, text string, ttl time.Duration) error {
	if ttl < 0 {
		return fmt.Errorf("clipboard: ttl must be non-negative")
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
	cmd := helperCommand{
		name: path,
		args: []string{helpercmd.CommandName, "--ttl", ttl.String()},
	}
	data := []byte(text)
	defer zeroBytes(data)
	return runner.Run(ctx, cmd, bytes.NewReader(data))
}

func (c *HelperClipboard) Clear(ctx context.Context) error {
	writer := NewSystemWriter()
	return writer.WriteClipboardBytes(ctx, nil)
}

const helperStartupTimeout = 750 * time.Millisecond

type processHelperRunner struct{}

func (processHelperRunner) Run(ctx context.Context, helper helperCommand, stdin io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(helper.name, helper.args...)
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = pipe.Close()
		killAndWait(cmd)
		return err
	}

	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(pipe, stdin)
		if closeErr := pipe.Close(); err == nil {
			err = closeErr
		}
		copyDone <- err
	}()

	select {
	case err := <-copyDone:
		if err != nil {
			killAndWait(cmd)
			return err
		}
	case <-ctx.Done():
		_ = pipe.Close()
		killAndWait(cmd)
		return ctx.Err()
	}

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	select {
	case err := <-waitDone:
		if err != nil {
			return fmt.Errorf("clipboard helper exited during startup: %w", err)
		}
		return nil
	case <-time.After(helperStartupTimeout):
		return nil
	}
}

func killAndWait(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

var _ out.Clipboard = (*HelperClipboard)(nil)
