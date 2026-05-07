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
	surface := mixHex(p.Bg, "#ffffff", 0.04)
	surfaceRaised := mixHex(p.Bg, "#ffffff", 0.08)
	inputBg := mixHex(p.Bg, "#ffffff", 0.10)
	fgMuted := mixHex(p.Fg, p.Bg, 0.25)
	divider := rgbaHex(p.Fg, 0.08)
	focus := p.Focus
	if strings.TrimSpace(focus) == "" {
		focus = p.Accent
	}
	accentGlow := rgbaHex(p.Accent, 0.18)
	accentHover := rgbaHex(p.Accent, 0.10)
	focusRing := rgbaHex(focus, 0.28)

	return fmt.Sprintf(`/* glsbw theme — auto-generated */
:root {
  --glsbw-scale: %.2f;

  --glsbw-bg: %s;
  --glsbw-surface: %s;
  --glsbw-surface-raised: %s;
  --glsbw-fg: %s;
  --glsbw-fg-muted: %s;
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
  --glsbw-divider: %s;
  --glsbw-accent-glow: %s;
  --glsbw-accent-hover: %s;
  --glsbw-focus: %s;
  --glsbw-focus-ring: %s;

  --glsbw-row-height: calc(var(--glsbw-scale) * 3.25em);
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
  border-radius: calc(var(--glsbw-radius) * 1.05);
  box-shadow: 0 20px 64px rgba(0, 0, 0, 0.55), 0 0 0 1px var(--glsbw-accent-glow);
  color: var(--glsbw-fg);
  padding: 0;
}

.glsbw-header,
.glsbw-category-bar {
  background-color: var(--glsbw-surface);
  border-bottom: 1px solid var(--glsbw-row-hover);
}

.glsbw-header {
  padding: calc(var(--glsbw-scale) * 0.45em) calc(var(--glsbw-scale) * 0.65em) 0;
}

.glsbw-category-bar {
  padding: calc(var(--glsbw-scale) * 0.45em) calc(var(--glsbw-scale) * 0.65em) calc(var(--glsbw-scale) * 0.65em);
}

.glsbw-omnibox button {
  background: none;
  background-color: var(--glsbw-surface-raised);
  background-image: none;
  border: 1px solid var(--glsbw-row-hover);
  border-radius: calc(var(--glsbw-scale) * 0.45em);
  box-shadow: none;
  color: var(--glsbw-fg);
  text-shadow: none;
}

.glsbw-omnibox button label {
  color: var(--glsbw-fg);
}

.glsbw-omnibox button:hover {
  background-color: var(--glsbw-accent-hover);
  background-image: none;
  border-color: var(--glsbw-accent);
}

.glsbw-omnibox button:focus {
  border-color: var(--glsbw-focus);
  box-shadow: 0 0 0 1px var(--glsbw-focus-ring);
}

button.glsbw-tab,
button.glsbw-category {
  background: none;
  background-image: none;
  color: var(--glsbw-fg-muted);
  min-height: 0;
}

button.glsbw-tab {
  background-color: transparent;
  border-style: solid;
  border-width: 0 0 calc(var(--glsbw-scale) * 0.14em) 0;
  border-color: transparent;
  border-radius: 0;
  padding: calc(var(--glsbw-scale) * 0.45em) calc(var(--glsbw-scale) * 0.85em);
}

button.glsbw-tab label {
  color: var(--glsbw-fg-muted);
}

button.glsbw-tab:hover {
  background-color: var(--glsbw-accent-hover);
  background-image: none;
}

button.glsbw-tab:hover label,
button.glsbw-tab.active label {
  color: var(--glsbw-fg);
}

button.glsbw-tab:focus {
  border-color: transparent transparent var(--glsbw-focus) transparent;
  box-shadow: none;
}

button.glsbw-tab.active {
  background-color: transparent;
  background-image: none;
  border-color: transparent transparent var(--glsbw-accent) transparent;
  color: var(--glsbw-fg);
}

button.glsbw-category {
  background-color: var(--glsbw-surface-raised);
  border: 1px solid transparent;
  border-radius: 999px;
  color: var(--glsbw-fg-muted);
  margin-right: calc(var(--glsbw-scale) * 0.35em);
  padding: calc(var(--glsbw-scale) * 0.20em) calc(var(--glsbw-scale) * 0.85em);
  font-size: 0.86em;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

button.glsbw-category label {
  color: var(--glsbw-fg-muted);
}

button.glsbw-category:hover {
  background-color: var(--glsbw-accent-hover);
  background-image: none;
  border-color: var(--glsbw-row-hover);
}

button.glsbw-category:hover label,
button.glsbw-category.active label {
  color: var(--glsbw-fg);
}

button.glsbw-category.active {
  background-color: var(--glsbw-row-selected);
  background-image: none;
  border-color: var(--glsbw-accent);
  color: var(--glsbw-fg);
}

.glsbw-search {
  background-color: var(--glsbw-surface);
  border: none;
  border-bottom: 1px solid var(--glsbw-row-hover);
  border-radius: 0;
  box-shadow: none;
  color: var(--glsbw-fg);
  font-size: 1rem;
  padding: calc(var(--glsbw-scale) * 0.75em) calc(var(--glsbw-scale) * 1em);
}

.glsbw-search:focus,
.glsbw-search:focus-within {
  border: none;
  border-bottom: 1px solid var(--glsbw-focus);
  box-shadow: none;
}

.glsbw-pin-unlock {
  padding: calc(var(--glsbw-scale) * 1em);
}

entry, passwordentry, searchentry, textview {
  background-color: var(--glsbw-bg-input);
  color: var(--glsbw-fg);
  border: 1px solid var(--glsbw-row-hover);
  border-radius: calc(var(--glsbw-scale) * 0.40em);
  padding: calc(var(--glsbw-scale) * 0.35em) calc(var(--glsbw-scale) * 0.65em);
}

spinbutton.glsbw-spin {
  background-color: var(--glsbw-bg-input);
  color: var(--glsbw-fg);
  border: 1px solid var(--glsbw-row-hover);
  border-radius: calc(var(--glsbw-scale) * 0.40em);
  padding: 0;
}

spinbutton.glsbw-spin text {
  background-color: transparent;
  color: var(--glsbw-fg);
  box-shadow: none;
  padding: calc(var(--glsbw-scale) * 0.35em) calc(var(--glsbw-scale) * 0.65em);
}

spinbutton.glsbw-spin button {
  background-image: none;
  box-shadow: none;
}

entry.glsbw-pin-entry {
  border-radius: calc(var(--glsbw-scale) * 0.55em);
  font-size: 1.35em;
  padding: calc(var(--glsbw-scale) * 0.70em) calc(var(--glsbw-scale) * 1em);
}

entry:focus, entry:focus-within,
passwordentry:focus, passwordentry:focus-within,
searchentry:focus, searchentry:focus-within,
textview:focus, textview:focus-within,
spinbutton.glsbw-spin:focus-within {
  border-color: var(--glsbw-focus);
  box-shadow: 0 0 0 1px var(--glsbw-focus-ring);
}

.glsbw-row {
  min-height: var(--glsbw-row-height);
  padding: calc(var(--glsbw-scale) * 0.55em) calc(var(--glsbw-scale) * 1em);
  border-left: 3px solid transparent;
  border-bottom: 1px solid var(--glsbw-divider);
  border-radius: 0;
  background-color: transparent;
}

.glsbw-row:hover {
  background-color: var(--glsbw-accent-hover);
}

.glsbw-row:selected,
.glsbw-row.selected {
  background-color: var(--glsbw-row-selected);
  border-left-color: var(--glsbw-accent);
}

.glsbw-title {
  font-weight: 600;
  color: var(--glsbw-fg);
}

.glsbw-subtitle {
  font-size: 0.85em;
  color: var(--glsbw-fg-muted);
}

.glsbw-badge {
  background-color: var(--glsbw-row-selected);
  border: 1px solid var(--glsbw-row-hover);
  border-radius: 999px;
  color: var(--glsbw-accent);
  font-size: 0.78em;
  font-weight: 600;
  letter-spacing: 0.04em;
  padding: 0.15em 0.55em;
  text-transform: uppercase;
}

.glsbw-empty {
  color: var(--glsbw-fg-muted);
  opacity: 0.90;
  padding: calc(var(--glsbw-scale) * 1.5em) var(--glsbw-padding);
}

.glsbw-status {
  color: var(--glsbw-fg-muted);
  font-size: 0.82em;
}

.glsbw-conflict {
  color: var(--glsbw-status-conflict);
}

.glsbw-error {
  color: var(--glsbw-status-danger);
}

.glsbw-footer {
  background-color: var(--glsbw-surface);
  border-top: 1px solid var(--glsbw-row-hover);
  padding: calc(var(--glsbw-scale) * 0.45em) calc(var(--glsbw-scale) * 1em);
}

.glsbw-hint {
  color: var(--glsbw-fg-muted);
  font-size: 0.78em;
  opacity: 0.85;
}

.glsbw-detail-title {
  color: var(--glsbw-fg);
  font-size: 1.08em;
  font-weight: 600;
}
`, scale,
		p.Bg, surface, surfaceRaised,
		p.Fg, fgMuted,
		p.Accent, p.AccentFg,
		p.RowHover, p.RowSelected,
		p.StatusOK, p.StatusPending, p.StatusWarning, p.StatusConflict, p.StatusDanger,
		inputBg, divider, accentGlow, accentHover, focus, focusRing)
}

func mixHex(color, target string, weight float64) string {
	r1, g1, b1, ok := parseHexColor(color)
	if !ok {
		return color
	}
	r2, g2, b2, ok := parseHexColor(target)
	if !ok {
		return color
	}
	weight = math.Min(1, math.Max(0, weight))
	return fmt.Sprintf(
		"#%02x%02x%02x",
		clampColor(float64(r1)*(1-weight)+float64(r2)*weight),
		clampColor(float64(g1)*(1-weight)+float64(g2)*weight),
		clampColor(float64(b1)*(1-weight)+float64(b2)*weight),
	)
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
