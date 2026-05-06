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

  --glsbw-row-height: calc(var(--glsbw-scale) * 3.25em);
  --glsbw-window-width: calc(var(--glsbw-scale) * 37em);
  --glsbw-padding: calc(var(--glsbw-scale) * 0.65em);
  --glsbw-radius: calc(var(--glsbw-scale) * 0.65em);
}

window {
  background-color: transparent;
}

* {
  outline-style: none;
  outline-width: 0;
  outline-color: transparent;
}

.glsbw-window {
  background-color: transparent;
  color: var(--glsbw-fg);
}

.glsbw-omnibox {
  background-color: var(--glsbw-bg);
  border: 1px solid var(--glsbw-row-hover);
  border-radius: var(--glsbw-radius);
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.50), 0 0 16px rgba(245, 158, 11, 0.08);
  color: var(--glsbw-fg);
  min-width: var(--glsbw-window-width);
  max-width: var(--glsbw-window-width);
  padding: 0;
}

.glsbw-search {
  background-color: transparent;
  border: none;
  border-bottom: 1px solid var(--glsbw-row-hover);
  border-radius: 0;
  box-shadow: none;
  color: var(--glsbw-fg);
  font-size: 1rem;
  padding: calc(var(--glsbw-scale) * 0.75em) calc(var(--glsbw-scale) * 1em);
}

.glsbw-search:focus, .glsbw-search:focus-within {
  border: none;
  border-bottom: 1px solid var(--glsbw-accent);
  box-shadow: none;
}

entry, passwordentry, searchentry, textview {
  background-color: #0a140f;
  color: var(--glsbw-fg);
  border: 1px solid var(--glsbw-row-hover);
  border-radius: calc(var(--glsbw-scale) * 0.40em);
  padding: calc(var(--glsbw-scale) * 0.35em) calc(var(--glsbw-scale) * 0.65em);
}

entry:focus, entry:focus-within,
passwordentry:focus, passwordentry:focus-within,
searchentry:focus, searchentry:focus-within,
textview:focus, textview:focus-within {
  border-color: var(--glsbw-accent);
  box-shadow: 0 0 0 1px rgba(245, 158, 11, 0.30);
}

.glsbw-row {
  min-height: var(--glsbw-row-height);
  padding: calc(var(--glsbw-scale) * 0.50em) calc(var(--glsbw-scale) * 1em);
  border-radius: 0;
  background-color: transparent;
}

.glsbw-row:hover {
  background-color: rgba(245, 158, 11, 0.06);
}

.glsbw-row:selected,
.glsbw-row.selected {
  background-color: var(--glsbw-row-selected);
}

.glsbw-title {
  font-weight: 500;
  color: var(--glsbw-fg);
}

.glsbw-subtitle {
  font-size: 0.85em;
  color: var(--glsbw-fg);
  opacity: 0.75;
}

.glsbw-badge {
  color: var(--glsbw-status-ok);
  font-size: 0.78em;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.glsbw-empty {
  color: var(--glsbw-status-ok);
  opacity: 0.75;
  padding: calc(var(--glsbw-scale) * 1.5em) var(--glsbw-padding);
}

.glsbw-status {
  color: var(--glsbw-status-ok);
  font-size: 0.82em;
}

.glsbw-conflict {
  color: var(--glsbw-status-conflict);
}

.glsbw-error {
  color: var(--glsbw-status-danger);
}

.glsbw-footer {
  border-top: 1px solid var(--glsbw-row-hover);
  padding: calc(var(--glsbw-scale) * 0.45em) calc(var(--glsbw-scale) * 1em);
}
`, scale,
		p.Bg, p.Fg, p.Accent, p.AccentFg,
		p.RowHover, p.RowSelected,
		p.StatusOK, p.StatusPending, p.StatusWarning, p.StatusConflict, p.StatusDanger)
}
