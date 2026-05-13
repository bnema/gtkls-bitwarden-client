package gtk

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeSoftLockService struct {
	trace *[]string
	err   error
}

func (f *fakeSoftLockService) SoftLock(context.Context) error {
	if f.trace != nil {
		*f.trace = append(*f.trace, "softlock")
	}
	return f.err
}

func TestSoftLockBeforeQuitRunsClearThenSoftLockThenQuit(t *testing.T) {
	trace := make([]string, 0, 3)
	svc := &fakeSoftLockService{trace: &trace}

	softLockBeforeQuit(context.Background(), svc,
		func() { trace = append(trace, "clear") },
		func() { trace = append(trace, "quit") },
	)

	require.Equal(t, []string{"clear", "softlock", "quit"}, trace)
}

func TestSoftLockBeforeQuitStillQuitsOnSoftLockError(t *testing.T) {
	trace := make([]string, 0, 4)
	svc := &fakeSoftLockService{trace: &trace, err: errors.New("boom")}

	softLockBeforeQuit(context.Background(), svc,
		func() { trace = append(trace, "clear") },
		func() { trace = append(trace, "quit") },
	)

	require.Equal(t, []string{"clear", "softlock", "quit"}, trace)
}
