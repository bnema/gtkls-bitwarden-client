//go:build linux && !nogtk

package omnibox

import (
	"os"
	"path/filepath"
	"testing"

	gtklib "github.com/bnema/puregotk/v4/gtk"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

func TestTypeIconPaintable_MaterializesSymbolicIcons(t *testing.T) {
	cacheHome := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	resetTypeIconStateForTest()

	for _, itemType := range []vault.ItemType{
		vault.ItemTypeLogin,
		vault.ItemTypeSecureNote,
		vault.ItemTypeCard,
		vault.ItemTypeIdentity,
	} {
		paintable, err := typeIconPaintable(string(itemType))
		if err != nil {
			t.Fatalf("typeIconPaintable(%q) error: %v", itemType, err)
		}
		if paintable == nil {
			t.Fatalf("typeIconPaintable(%q) returned nil", itemType)
		}
		if !paintable.IsSymbolic() {
			t.Fatalf("typeIconPaintable(%q) should be symbolic", itemType)
		}
	}

	for _, filename := range []string{
		"login-symbolic.svg",
		"note-symbolic.svg",
		"card-symbolic.svg",
		"identity-symbolic.svg",
	} {
		path := filepath.Join(cacheHome, "gtkls-bitwarden-client", "type-row-icons-v1", filename)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected materialized icon %q: %v", path, err)
		}
	}
}

func resetTypeIconStateForTest() {
	typeIconMu.Lock()
	defer typeIconMu.Unlock()
	materializedTypeIconsDir = ""
	cachedTypeIconPaintables = map[string]*gtklib.IconPaintable{}
}
