package clipboard

import (
	"errors"
	"os/exec"
	"strings"
)

var ErrClipboardUnavailable = errors.New("clipboard: no clipboard backend available")

func NewWaylandPreferred(fallbackSet Setter, fallbackClear Clearer) *Adapter {
	return New(preferSetter(wlCopySetter(), fallbackSet), preferClearer(wlCopyClearer(), fallbackClear))
}

func preferSetter(primary, fallback Setter) Setter {
	return func(text string) error {
		if primary != nil {
			if err := primary(text); err == nil {
				return nil
			} else if fallback == nil {
				return err
			}
		}
		if fallback != nil {
			return fallback(text)
		}
		return ErrClipboardUnavailable
	}
}

func preferClearer(primary, fallback Clearer) Clearer {
	return func() error {
		if primary != nil {
			if err := primary(); err == nil {
				return nil
			} else if fallback == nil {
				return err
			}
		}
		if fallback != nil {
			return fallback()
		}
		return ErrClipboardUnavailable
	}
}

func wlCopySetter() Setter {
	if _, err := exec.LookPath("wl-copy"); err != nil {
		return nil
	}
	return func(text string) error {
		cmd := exec.Command("wl-copy", "--trim-newline", "--sensitive")
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
}

func wlCopyClearer() Clearer {
	if _, err := exec.LookPath("wl-copy"); err != nil {
		return nil
	}
	return func() error {
		return exec.Command("wl-copy", "--clear").Run()
	}
}
