package clipboard

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type helperCommand struct {
	name string
	args []string
}

type helperRunner interface {
	Run(ctx context.Context, cmd helperCommand, stdin io.Reader) error
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
