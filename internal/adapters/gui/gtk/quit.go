package gtk

import (
	"context"

	safelog "github.com/bnema/gtk4-layershell-bitwarden/internal/core/logging"
	"github.com/bnema/zerowrap"
)

type softLocker interface {
	SoftLock(context.Context) error
}

func softLockBeforeQuit(ctx context.Context, locker softLocker, clearFn func(), quit func()) {
	if clearFn != nil {
		clearFn()
	}
	if locker != nil {
		logOverlayInfo(ctx, "soft_lock_before_quit", "soft-locking before overlay quit")
		if err := locker.SoftLock(context.WithoutCancel(ctx)); err != nil {
			logOverlayError(ctx, "soft_lock_before_quit", err)
		}
	}
	if quit != nil {
		quit()
	}
}

func logOverlayInfo(ctx context.Context, operation, message string) {
	log := zerowrap.FromCtx(ctx).WithFields(map[string]any{
		zerowrap.FieldComponent: "gui.gtk",
		zerowrap.FieldOperation: operation,
	})
	log.Info().Msg(message)
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
