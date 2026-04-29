//go:build linux && !nogtk

package omnibox

import "github.com/bnema/puregotk/v4/glib"

// idleAddOnce schedules fn to run once on the GTK main thread.
func idleAddOnce(fn func()) {
	onceFn := glib.SourceOnceFunc(func(uintptr) { fn() })
	glib.IdleAddOnce(&onceFn, 0)
}
