package gtk

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeSoftLockService struct {
	calls []string
	err   error
}

func (f *fakeSoftLockService) SoftLock(context.Context) error {
	f.calls = append(f.calls, "softlock")
	return f.err
}

func TestSoftLockBeforeQuitRunsClearThenSoftLockThenQuit(t *testing.T) {
	svc := &fakeSoftLockService{}
	calls := make([]string, 0, 3)

	softLockBeforeQuit(context.Background(), svc,
		func() { calls = append(calls, "clear") },
		func() { calls = append(calls, "quit") },
		func(error) { calls = append(calls, "log") },
	)

	require.Equal(t, []string{"clear", "quit"}, calls)
	require.Equal(t, []string{"softlock"}, svc.calls)
}

func TestSoftLockBeforeQuitStillQuitsOnSoftLockError(t *testing.T) {
	svc := &fakeSoftLockService{err: errors.New("boom")}
	calls := make([]string, 0, 3)

	softLockBeforeQuit(context.Background(), svc,
		func() { calls = append(calls, "clear") },
		func() { calls = append(calls, "quit") },
		func(error) { calls = append(calls, "log") },
	)

	require.Equal(t, []string{"clear", "log", "quit"}, calls)
	require.Equal(t, []string{"softlock"}, svc.calls)
}
