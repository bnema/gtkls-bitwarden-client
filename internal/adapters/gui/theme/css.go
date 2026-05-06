package theme

import (
	"fmt"
	"math"

	coretheme "github.com/bnema/gtk4-layershell-bitwarden/internal/core/theme"
)

// BuildCSS generates a CSS string for the given palette and scale factor.
// scale is clamped to [0.5, 3.0]; values <= 0 are treated as 1.0.
func BuildCSS(p coretheme.Palette, scale float64) string {
	if scale <= 0 {
		scale = 1.0
	}
	scale = math.Round(math.Min(3.0, math.Max(0.5, scale))*100) / 100

	return fmt.Sprintf(`/* glsbw theme — auto-generated */
:root {
  --glsbw-scale: %.2f;

  --glsbw-bg: %s;
  --glsbw-fg: %s;
  --glsbw-accent: %s;
  --glsbw-accent-fg: %s;
  --glsbw-row-hover: %s;
  --glsbw-row-selected: %s;
  --glsbw-status-ok: %s;
  --glsbw-status-pending: %s;
  --glsbw-status-warning: %s;
  --glsbw-status-conflict: %s;
  --glsbw-status-danger: %s;

  --glsbw-row-height: calc(var(--glsbw-scale) * 3em);
  --glsbw-window-width: calc(var(--glsbw-scale) * 20em);
  --glsbw-padding: calc(var(--glsbw-scale) * 0.5em);
  --glsbw-radius: calc(var(--glsbw-scale) * 0.25em);
}

.glsbw-window {
  background-color: var(--glsbw-bg);
  color: var(--glsbw-fg);
  width: var(--glsbw-window-width);
  padding: var(--glsbw-padding);
}

.glsbw-omnibox {
  background-color: var(--glsbw-row-hover);
  border-radius: var(--glsbw-radius);
  padding: var(--glsbw-padding);
}

.glsbw-search {
  background-color: var(--glsbw-row-hover);
  border: 1px solid var(--glsbw-accent);
  border-radius: var(--glsbw-radius);
  color: var(--glsbw-fg);
}

entry, passwordentry, searchentry, textview {
  background-color: var(--glsbw-bg);
  color: var(--glsbw-fg);
  border: 1px solid var(--glsbw-row-hover);
  border-radius: var(--glsbw-radius);
  padding: calc(var(--glsbw-scale) * 0.25em) calc(var(--glsbw-scale) * 0.5em);
}

entry:focus, entry:focus-within,
passwordentry:focus, passwordentry:focus-within,
searchentry:focus, searchentry:focus-within,
textview:focus, textview:focus-within {
  border-color: var(--glsbw-accent);
  box-shadow: 0 0 0 1px var(--glsbw-accent);
}

.glsbw-row {
  height: var(--glsbw-row-height);
  padding: var(--glsbw-padding);
  border-radius: var(--glsbw-radius);
}

.glsbw-row:hover {
  background-color: var(--glsbw-row-hover);
}

.glsbw-row:selected,
.glsbw-row.selected {
  background-color: var(--glsbw-row-selected);
}

.glsbw-title {
  font-weight: bold;
  color: var(--glsbw-fg);
}

.glsbw-subtitle {
  font-size: 0.85em;
  color: var(--glsbw-fg);
  opacity: 0.75;
}

.glsbw-status {
  color: var(--glsbw-status-ok);
}

.glsbw-conflict {
  color: var(--glsbw-status-conflict);
}

.glsbw-error {
  color: var(--glsbw-status-danger);
}

.glsbw-footer {
  border-top: 1px solid var(--glsbw-row-hover);
  padding: var(--glsbw-padding);
}
`, scale,
		p.Bg, p.Fg, p.Accent, p.AccentFg,
		p.RowHover, p.RowSelected,
		p.StatusOK, p.StatusPending, p.StatusWarning, p.StatusConflict, p.StatusDanger)
}
