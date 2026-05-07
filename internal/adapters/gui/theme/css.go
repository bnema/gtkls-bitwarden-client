package theme

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	coretheme "github.com/bnema/gtk4-layershell-bitwarden/internal/core/theme"
)

// BuildCSS generates a CSS string for the given palette and scale factor.
// scale is clamped to [0.5, 3.0]; values <= 0 are treated as 1.0.
func BuildCSS(p coretheme.Palette, scale float64) string {
	if scale <= 0 {
		scale = 1.0
	}
	scale = math.Round(math.Min(3.0, math.Max(0.5, scale))*100) / 100
	inputBg := darkenHex(p.Bg, 0.78)
	accentGlow := rgbaHex(p.Accent, 0.08)
	accentHover := rgbaHex(p.Accent, 0.06)
	accentFocus := rgbaHex(p.Accent, 0.30)

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
  --glsbw-bg-input: %s;
  --glsbw-accent-glow: %s;
  --glsbw-accent-hover: %s;
  --glsbw-accent-focus: %s;

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
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.50), 0 0 16px var(--glsbw-accent-glow);
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
  background-color: var(--glsbw-bg-input);
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
  box-shadow: 0 0 0 1px var(--glsbw-accent-focus);
}

.glsbw-row {
  min-height: var(--glsbw-row-height);
  padding: calc(var(--glsbw-scale) * 0.50em) calc(var(--glsbw-scale) * 1em);
  border-radius: 0;
  background-color: transparent;
}

.glsbw-row:hover {
  background-color: var(--glsbw-accent-hover);
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
		p.StatusOK, p.StatusPending, p.StatusWarning, p.StatusConflict, p.StatusDanger,
		inputBg, accentGlow, accentHover, accentFocus)
}

func darkenHex(color string, factor float64) string {
	r, g, b, ok := parseHexColor(color)
	if !ok {
		return color
	}
	return fmt.Sprintf("#%02x%02x%02x", clampColor(float64(r)*factor), clampColor(float64(g)*factor), clampColor(float64(b)*factor))
}

func rgbaHex(color string, alpha float64) string {
	r, g, b, ok := parseHexColor(color)
	if !ok {
		return color
	}
	return fmt.Sprintf("rgba(%d, %d, %d, %.2f)", r, g, b, math.Min(1, math.Max(0, alpha)))
}

func parseHexColor(color string) (r, g, b int, ok bool) {
	hex := strings.TrimPrefix(strings.TrimSpace(color), "#")
	if len(hex) == 3 {
		hex = strings.Repeat(hex[0:1], 2) + strings.Repeat(hex[1:2], 2) + strings.Repeat(hex[2:3], 2)
	}
	if len(hex) != 6 {
		return 0, 0, 0, false
	}
	value, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return int(value >> 16), int(value>>8) & 0xff, int(value) & 0xff, true
}

func clampColor(value float64) int {
	return int(math.Round(math.Min(255, math.Max(0, value))))
}
