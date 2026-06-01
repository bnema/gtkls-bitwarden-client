//go:build linux && !nogtk

package omnibox

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"
	"sync"

	"github.com/bnema/puregotk/v4/gio"
	gobject "github.com/bnema/puregotk/v4/gobject"
	gtklib "github.com/bnema/puregotk/v4/gtk"

	"github.com/bnema/gtkls-bitwarden-client/internal/adapters/paths/xdg"
	"github.com/bnema/gtkls-bitwarden-client/internal/core/vault"
)

const typeIconSize = 18

var (
	//go:embed icons/login-symbolic.svg
	loginTypeIconSVG []byte
	//go:embed icons/note-symbolic.svg
	noteTypeIconSVG []byte
	//go:embed icons/card-symbolic.svg
	cardTypeIconSVG []byte
	//go:embed icons/identity-symbolic.svg
	identityTypeIconSVG []byte

	typeIconAssets = map[string]embeddedTypeIconAsset{
		string(vault.ItemTypeLogin):      {filename: "login-symbolic.svg", data: loginTypeIconSVG},
		string(vault.ItemTypeSecureNote): {filename: "note-symbolic.svg", data: noteTypeIconSVG},
		string(vault.ItemTypeCard):       {filename: "card-symbolic.svg", data: cardTypeIconSVG},
		string(vault.ItemTypeIdentity):   {filename: "identity-symbolic.svg", data: identityTypeIconSVG},
	}

	typeIconMu               sync.Mutex
	materializedTypeIconsDir string
	cachedTypeIconPaintables = map[string]*gtklib.IconPaintable{}
)

type embeddedTypeIconAsset struct {
	filename string
	data     []byte
}

func buildTypeIcon(itemType string) *gtklib.Image {
	paintable, err := typeIconPaintable(itemType)
	if err != nil || paintable == nil {
		return nil
	}

	image := gtklib.NewImageFromPaintable(paintable)
	if image == nil {
		return nil
	}
	image.GetStyleContext().AddClass("glsbw-type-icon")
	image.SetSizeRequest(typeIconSize, typeIconSize)
	image.SetHalign(gtklib.AlignCenterValue)
	image.SetValign(gtklib.AlignCenterValue)
	return image
}

func typeIconPaintable(itemType string) (*gtklib.IconPaintable, error) {
	asset, ok := typeIconAssets[itemType]
	if !ok {
		return nil, nil
	}

	typeIconMu.Lock()
	defer typeIconMu.Unlock()

	if paintable, ok := cachedTypeIconPaintables[itemType]; ok {
		return paintable, nil
	}

	dir, err := ensureTypeIconsMaterializedLocked()
	if err != nil {
		return nil, err
	}
	file := gio.FileNewForPath(filepath.Join(dir, asset.filename))
	if file == nil {
		return nil, nil
	}
	defer gobject.ObjectNewFromInternalPtr(file.GoPointer()).Unref()

	paintable := gtklib.NewIconPaintableForFile(file, typeIconSize, 1)
	if paintable == nil {
		return nil, nil
	}
	cachedTypeIconPaintables[itemType] = paintable
	return paintable, nil
}

func ensureTypeIconsMaterializedLocked() (string, error) {
	if materializedTypeIconsDir != "" {
		return materializedTypeIconsDir, nil
	}

	dir := filepath.Join(xdg.Default().CacheDir(), "type-row-icons-v1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, asset := range typeIconAssets {
		path := filepath.Join(dir, asset.filename)
		if err := writeMaterializedTypeIcon(path, asset.data); err != nil {
			return "", err
		}
	}
	materializedTypeIconsDir = dir
	return materializedTypeIconsDir, nil
}

func writeMaterializedTypeIcon(path string, data []byte) error {
	existing, err := os.ReadFile(path)
	if err == nil && bytes.Equal(existing, data) {
		return nil
	}
	return os.WriteFile(path, data, 0o644)
}
