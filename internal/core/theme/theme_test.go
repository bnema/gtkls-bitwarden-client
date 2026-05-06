package theme

import (
	"testing"
)

func TestDefaultAccent(t *testing.T) {
	p := DefaultDarkPalette()
	if p.Accent != "#f59e0b" {
		t.Errorf("expected accent #f59e0b, got %s", p.Accent)
	}
}

func TestDefaultBg(t *testing.T) {
	p := DefaultDarkPalette()
	if p.Bg != "#0f1a16" {
		t.Errorf("expected bg #0f1a16, got %s", p.Bg)
	}
}

func TestApplyOverrideAccent(t *testing.T) {
	p := DefaultDarkPalette()
	overrides := map[string]string{"accent": "#ff0000"}
	result := ApplyOverrides(p, overrides)

	if result.Accent != "#ff0000" {
		t.Errorf("expected accent #ff0000, got %s", result.Accent)
	}
	// Other fields should remain unchanged
	if result.Bg != "#0f1a16" {
		t.Errorf("expected bg unchanged #0f1a16, got %s", result.Bg)
	}
}

func TestApplyOverrideEmptyValue(t *testing.T) {
	p := DefaultDarkPalette()
	overrides := map[string]string{"accent": ""}
	result := ApplyOverrides(p, overrides)

	if result.Accent != "#f59e0b" {
		t.Errorf("expected accent unchanged #f59e0b for empty override, got %s", result.Accent)
	}
}

func TestApplyOverrideAllFields(t *testing.T) {
	p := DefaultDarkPalette()
	overrides := map[string]string{
		"bg":              "#000000",
		"fg":              "#ffffff",
		"accent":          "#00ff00",
		"accent_fg":       "#000000",
		"row_hover":       "#111111",
		"row_selected":    "#222222",
		"status_ok":       "#00ff00",
		"status_pending":  "#ffff00",
		"status_warning":  "#ff8800",
		"status_conflict": "#ff0000",
		"status_danger":   "#cc0000",
	}
	result := ApplyOverrides(p, overrides)

	if result.Bg != "#000000" {
		t.Errorf("bg = %s", result.Bg)
	}
	if result.Fg != "#ffffff" {
		t.Errorf("fg = %s", result.Fg)
	}
	if result.Accent != "#00ff00" {
		t.Errorf("accent = %s", result.Accent)
	}
	if result.AccentFg != "#000000" {
		t.Errorf("accent_fg = %s", result.AccentFg)
	}
	if result.RowHover != "#111111" {
		t.Errorf("row_hover = %s", result.RowHover)
	}
	if result.RowSelected != "#222222" {
		t.Errorf("row_selected = %s", result.RowSelected)
	}
	if result.StatusOK != "#00ff00" {
		t.Errorf("status_ok = %s", result.StatusOK)
	}
	if result.StatusPending != "#ffff00" {
		t.Errorf("status_pending = %s", result.StatusPending)
	}
	if result.StatusWarning != "#ff8800" {
		t.Errorf("status_warning = %s", result.StatusWarning)
	}
	if result.StatusConflict != "#ff0000" {
		t.Errorf("status_conflict = %s", result.StatusConflict)
	}
	if result.StatusDanger != "#cc0000" {
		t.Errorf("status_danger = %s", result.StatusDanger)
	}
}

func TestApplyOverrideNoOverrides(t *testing.T) {
	p := DefaultDarkPalette()
	result := ApplyOverrides(p, nil)
	if result.Accent != "#f59e0b" {
		t.Errorf("expected accent unchanged with nil overrides, got %s", result.Accent)
	}
}

func TestPaletteMap(t *testing.T) {
	p := DefaultDarkPalette()
	m := p.Map()
	if m["accent"] != "#f59e0b" {
		t.Errorf("expected accent in map, got %s", m["accent"])
	}
	if len(m) != 11 {
		t.Errorf("expected 11 keys in map, got %d", len(m))
	}
}

func TestPaletteFieldValue(t *testing.T) {
	p := DefaultDarkPalette()
	if p.FieldValue("accent") != "#f59e0b" {
		t.Errorf("FieldValue accent = %s", p.FieldValue("accent"))
	}
	if p.FieldValue("nonexistent") != "" {
		t.Errorf("FieldValue nonexistent should be empty")
	}
}
