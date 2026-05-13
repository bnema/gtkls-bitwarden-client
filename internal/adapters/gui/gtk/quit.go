package gtk

import (
	"context"

	safelog "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
	"github.com/bnema/zerowrap"
)

type softLocker interface {
	SoftLock(context.Context) error
}

func softLockBeforeQuit(ctx context.Context, locker softLocker, clearFn func(), quit func(), logf func(error)) {
	if clearFn != nil {
		clearFn()
	}
	if locker != nil {
		if err := locker.SoftLock(context.WithoutCancel(ctx)); err != nil && logf != nil {
			logf(err)
		}
	}
	if quit != nil {
		quit()
	}
}

func logOverlayError(ctx context.Context, operation string, err error) {
	if err == nil {
		return
	}
	log := zerowrap.FromCtx(ctx).WithFields(map[string]any{
		zerowrap.FieldComponent: "gui.gtk",
		zerowrap.FieldOperation: operation,
	})
	log.Error().
		Str("error_kind", safelog.SafeErrorKind(err)).
		Str("error_detail", safelog.SafeErrorDetail(err)).
		Msg("overlay operation failed")
}
