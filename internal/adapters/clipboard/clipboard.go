// Package clipboard provides a TTL-based clipboard adapter implementing out.Clipboard.
package clipboard

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bnema/gtkls-bitwarden-client/internal/ports/out"
)

var ErrClipboardUnavailable = errors.New("clipboard: no clipboard backend available")

// Setter is a function that sets the clipboard text.
type Setter func(string) error

// Clearer is a function that clears the clipboard.
type Clearer func() error

// Adapter implements out.Clipboard with optional TTL-based auto-clear.
type Adapter struct {
	mu      sync.Mutex
	setter  Setter
	clearer Clearer
	timer   *time.Timer
	value   string
	gen     uint64
}

// New returns a new Adapter. If set or clear is nil, safe in-memory defaults
// are used so that tests and headless environments work without a real clipboard.
func New(set Setter, clear Clearer) *Adapter {
	if set == nil {
		set = func(s string) error { return nil }
	}
	if clear == nil {
		clear = func() error { return nil }
	}
	return &Adapter{setter: set, clearer: clear}
}

// Set writes text to the clipboard and, if ttl > 0, schedules a Clear after
// ttl. Any previously scheduled timer is cancelled. Respects ctx before setting.
func (a *Adapter) Set(ctx context.Context, text string, ttl time.Duration) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Cancel any previous clear timer and advance the generation. Stop alone is
	// not sufficient once a timer callback has fired and is waiting on a.mu; the
	// generation check prevents that stale callback from clearing newer content.
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.gen++
	generation := a.gen

	if err := a.setter(text); err != nil {
		return err
	}

	a.value = text

	if ttl > 0 {
		a.timer = time.AfterFunc(ttl, func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			if generation != a.gen {
				return
			}
			_ = a.clearer()
			a.value = ""
			a.timer = nil
		})
	}

	return nil
}

// Clear cancels any pending timer and clears the clipboard. It respects context
// cancellation: if ctx is already done the operation is skipped.
func (a *Adapter) Clear(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.gen++

	a.value = ""
	return a.clearer()
}

// compile-time check
var _ out.Clipboard = (*Adapter)(nil)
