//go:build linux && !nogtk

package gtk

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/bnema/puregotk/v4/gdk"
	"github.com/bnema/puregotk/v4/gio"
	gtklib "github.com/bnema/puregotk/v4/gtk"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/gui/layershell"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/gui/omnibox"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/adapters/gui/theme"
	coretheme "github.com/bnema/gtk4-layershell-bitwarden/internal/core/theme"
	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

// Options configures the GTK overlay application.
type Options struct {
	Namespace string
	AppID     string
	Version   string
}

// Overlay is the GTK4 layer-shell overlay shell. It implements the headless
// overlay window that runs the application UI.
type Overlay struct {
	service   in.AppService
	opts      Options
	callbacks []interface{}

	runMu  sync.Mutex
	runErr error
}

// NewOverlay creates a new Overlay with the given service and options.
func NewOverlay(service in.AppService, opts Options) *Overlay {
	return &Overlay{
		service: service,
		opts:    opts,
	}
}

// GTKAvailable checks whether a GTK display is available, returning false if
// not (e.g. no display server). It recovers from any panic.
func GTKAvailable() bool {
	defer func() {
		recover()
	}()
	return gtklib.InitCheck()
}

// Run starts the GTK main loop. It blocks until the application is quit or
// the context is cancelled.
func (o *Overlay) Run(ctx context.Context) error {
	if o.service == nil {
		return fmt.Errorf("gtk overlay: service is nil")
	}
	if !GTKAvailable() {
		return fmt.Errorf("gtk overlay: GTK display not available")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	appID := o.opts.AppID
	if appID == "" {
		appID = "dev.bnema.gtk4-layershell-bitwarden"
	}

	app := gtklib.NewApplication(&appID, gio.GApplicationNonUniqueValue)

	var ob *omnibox.View

	activateCb := func(_ gio.Application) {
		window := gtklib.NewApplicationWindow(app)

		title := "Bitwarden"
		window.SetTitle(&title)
		window.SetDecorated(false)

		// Configure layer-shell overlay.
		namespace := o.opts.Namespace
		if namespace == "" {
			namespace = "gtk4-layershell-bitwarden"
		}
		if !layershell.InitOverlay(&window.Window, layershell.OverlayConfig{
			Namespace:         namespace,
			ExclusiveKeyboard: true,
		}) {
			o.runMu.Lock()
			o.runErr = fmt.Errorf("gtk overlay: layer-shell is not available")
			o.runMu.Unlock()
			app.Quit()
			return
		}

		// Attach CSS theming.
		cssProvider := gtklib.NewCssProvider()
		scale := 1.0
		if cfg := o.service.Config(); cfg != nil {
			scale = cfg.Appearance.UIScale
		}
		css := theme.BuildCSS(coretheme.DefaultDarkPalette(), scale)
		cssProvider.LoadFromString(css)
		if display := gdk.DisplayGetDefault(); display != nil {
			gtklib.StyleContextAddProviderForDisplay(display, cssProvider, 800)
		}

		// Center the omnibox root box.
		centerBox := gtklib.NewBox(gtklib.OrientationVerticalValue, 0)
		centerBox.SetHalign(gtklib.AlignCenterValue)
		centerBox.SetValign(gtklib.AlignCenterValue)

		styleCtx := centerBox.GetStyleContext()
		styleCtx.AddClass("glsbw-window")

		// Create the omnibox View. It builds its own widgets and manages its
		// own lifecycle via the context.
		ob = omnibox.New(ctx, o.service, func() { app.Quit() }, o.retain)
		centerBox.Append(&ob.Root.Widget)

		window.SetChild(&centerBox.Widget)

		// Attach keyboard controller to the window.
		ob.AttachKeyController(&window.Window)

		// Close request quits the application.
		closeCb := func(_ gtklib.Window) bool {
			app.Quit()
			return true
		}
		o.retain(closeCb)
		window.ConnectCloseRequest(&closeCb)

		window.Show()

		// Focus the omnibox.
		ob.GrabFocus()
	}
	o.retain(activateCb)
	app.ConnectActivate(&activateCb)

	// Handle context cancellation (quit the app).
	go func() {
		<-ctx.Done()
		idleAddOnce(func() { app.Quit() })
	}()

	app.Run(0, nil)

	o.runMu.Lock()
	err := o.runErr
	o.runMu.Unlock()

	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// retain appends cb to the callbacks slice to prevent the Go GC from
// collecting callbacks that GTK still references via C pointers.
func (o *Overlay) retain(cb interface{}) {
	o.callbacks = append(o.callbacks, cb)
}
