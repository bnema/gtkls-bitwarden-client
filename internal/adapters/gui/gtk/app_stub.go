//go:build !linux || nogtk

package gtk

import (
	"context"
	"fmt"

	"github.com/bnema/gtkls-bitwarden-client/internal/ports/in"
)

// Options configures the GTK overlay application.
type Options struct {
	Namespace string
	AppID     string
	Version   string
}

// Overlay is a no-op stub on non-Linux or nogtk builds.
type Overlay struct{}

// NewOverlay creates a new Overlay stub.
func NewOverlay(_ in.AppService, _ Options) *Overlay {
	return &Overlay{}
}

// GTKAvailable returns false on non-Linux or nogtk builds.
func GTKAvailable() bool { return false }

// Run returns an error indicating that GTK overlay requires Linux.
func (o *Overlay) Run(_ context.Context) error {
	return fmt.Errorf("gtk overlay requires Linux GTK4 layer-shell support")
}
