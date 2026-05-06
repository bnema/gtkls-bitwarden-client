package theme

import "strings"

type Palette struct {
	Bg             string
	Fg             string
	Accent         string
	AccentFg       string
	RowHover       string
	RowSelected    string
	StatusOK       string
	StatusPending  string
	StatusWarning  string
	StatusConflict string
	StatusDanger   string
}

// DefaultDarkPalette returns the default dark emerald/amber overlay palette.
func DefaultDarkPalette() Palette {
	return Palette{
		Bg:             "#0f1a16",
		Fg:             "#c8e8d8",
		Accent:         "#f59e0b",
		AccentFg:       "#0f1a16",
		RowHover:       "#1a3028",
		RowSelected:    "rgba(245, 158, 11, 0.10)",
		StatusOK:       "#4a7a66",
		StatusPending:  "#f59e0b",
		StatusWarning:  "#d97706",
		StatusConflict: "#f59e0b",
		StatusDanger:   "#E5484D",
	}
}

// ApplyOverrides returns a copy of p with any non-empty values from overrides applied.
// The overrides map uses snake_case keys matching the Palette field names:
// bg, fg, accent, accent_fg, row_hover, row_selected,
// status_ok, status_pending, status_warning, status_conflict, status_danger.
func ApplyOverrides(p Palette, overrides map[string]string) Palette {
	if len(overrides) == 0 {
		return p
	}
	if v, ok := overrides["bg"]; ok && v != "" {
		p.Bg = v
	}
	if v, ok := overrides["fg"]; ok && v != "" {
		p.Fg = v
	}
	if v, ok := overrides["accent"]; ok && v != "" {
		p.Accent = v
	}
	if v, ok := overrides["accent_fg"]; ok && v != "" {
		p.AccentFg = v
	}
	if v, ok := overrides["row_hover"]; ok && v != "" {
		p.RowHover = v
	}
	if v, ok := overrides["row_selected"]; ok && v != "" {
		p.RowSelected = v
	}
	if v, ok := overrides["status_ok"]; ok && v != "" {
		p.StatusOK = v
	}
	if v, ok := overrides["status_pending"]; ok && v != "" {
		p.StatusPending = v
	}
	if v, ok := overrides["status_warning"]; ok && v != "" {
		p.StatusWarning = v
	}
	if v, ok := overrides["status_conflict"]; ok && v != "" {
		p.StatusConflict = v
	}
	if v, ok := overrides["status_danger"]; ok && v != "" {
		p.StatusDanger = v
	}
	return p
}

// Map returns the palette as a map for use with GTK CSS or theme engines.
func (p Palette) Map() map[string]string {
	return map[string]string{
		"bg":              p.Bg,
		"fg":              p.Fg,
		"accent":          p.Accent,
		"accent_fg":       p.AccentFg,
		"row_hover":       p.RowHover,
		"row_selected":    p.RowSelected,
		"status_ok":       p.StatusOK,
		"status_pending":  p.StatusPending,
		"status_warning":  p.StatusWarning,
		"status_conflict": p.StatusConflict,
		"status_danger":   p.StatusDanger,
	}
}

// FieldValue returns the palette value for a given snake_case field name.
func (p Palette) FieldValue(field string) string {
	switch strings.ToLower(field) {
	case "bg":
		return p.Bg
	case "fg":
		return p.Fg
	case "accent":
		return p.Accent
	case "accent_fg":
		return p.AccentFg
	case "row_hover":
		return p.RowHover
	case "row_selected":
		return p.RowSelected
	case "status_ok":
		return p.StatusOK
	case "status_pending":
		return p.StatusPending
	case "status_warning":
		return p.StatusWarning
	case "status_conflict":
		return p.StatusConflict
	case "status_danger":
		return p.StatusDanger
	default:
		return ""
	}
}
