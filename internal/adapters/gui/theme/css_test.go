package theme

import (
	"strings"
	"testing"

	coretheme "github.com/bnema/gtk4-layershell-bitwarden/internal/core/theme"
)

func TestBuildCSS_DefaultDarkPalette_Scale1_2(t *testing.T) {
	css := BuildCSS(coretheme.DefaultDarkPalette(), 1.2)

	if !strings.Contains(css, "--glsbw-scale: 1.20") {
		t.Errorf("expected --glsbw-scale: 1.20 in CSS, got:\n%s", css)
	}
	if !strings.Contains(css, "em") {
		t.Errorf("expected em unit in CSS")
	}
	if !strings.Contains(css, "#f59e0b") {
		t.Errorf("expected #f59e0b accent in CSS")
	}
	if !strings.Contains(css, ".glsbw-window") {
		t.Errorf("expected .glsbw-window selector")
	}
	if !strings.Contains(css, ".glsbw-omnibox") {
		t.Errorf("expected .glsbw-omnibox selector")
	}
	if !strings.Contains(css, ".glsbw-search") {
		t.Errorf("expected .glsbw-search selector")
	}
	if !strings.Contains(css, ".glsbw-header") {
		t.Errorf("expected .glsbw-header selector")
	}
	if !strings.Contains(css, "button.glsbw-tab") {
		t.Errorf("expected themed button.glsbw-tab selector")
	}
	if !strings.Contains(css, "button.glsbw-category") {
		t.Errorf("expected themed button.glsbw-category selector")
	}
	if !strings.Contains(css, "background-image: none") {
		t.Errorf("expected native GTK button backgrounds to be disabled")
	}
	if !strings.Contains(css, ".glsbw-row") {
		t.Errorf("expected .glsbw-row selector")
	}
	if !strings.Contains(css, "entry, passwordentry, searchentry, textview") {
		t.Errorf("expected dark input selectors")
	}
	if !strings.Contains(css, ".glsbw-title") {
		t.Errorf("expected .glsbw-title selector")
	}
	if !strings.Contains(css, ".glsbw-badge") {
		t.Errorf("expected .glsbw-badge selector")
	}
	if !strings.Contains(css, ".glsbw-subtitle") {
		t.Errorf("expected .glsbw-subtitle selector")
	}
	if !strings.Contains(css, ".glsbw-empty") {
		t.Errorf("expected .glsbw-empty selector")
	}
	if !strings.Contains(css, ".glsbw-status") {
		t.Errorf("expected .glsbw-status selector")
	}
	if !strings.Contains(css, ".glsbw-conflict") {
		t.Errorf("expected .glsbw-conflict selector")
	}
	if !strings.Contains(css, ".glsbw-error") {
		t.Errorf("expected .glsbw-error selector")
	}
	if !strings.Contains(css, ".glsbw-footer") {
		t.Errorf("expected .glsbw-footer selector")
	}
	if !strings.Contains(css, ".glsbw-hint") {
		t.Errorf("expected .glsbw-hint selector")
	}
	if strings.Contains(css, "max-width") {
		t.Errorf("GTK CSS does not support max-width; use widget sizing instead")
	}
}

func TestBuildCSS_ClampsLowScale(t *testing.T) {
	css := BuildCSS(coretheme.DefaultDarkPalette(), 0)
	if !strings.Contains(css, "--glsbw-scale: 1.00") {
		t.Errorf("expected scale clamped to 1.00 for input 0, got:\n%s", css)
	}

	css = BuildCSS(coretheme.DefaultDarkPalette(), 0.4)
	if !strings.Contains(css, "--glsbw-scale: 0.50") {
		t.Errorf("expected scale clamped to 0.50 for input 0.4, got:\n%s", css)
	}
}

func TestBuildCSS_ClampsHighScale(t *testing.T) {
	css := BuildCSS(coretheme.DefaultDarkPalette(), 5.0)
	if !strings.Contains(css, "--glsbw-scale: 3.00") {
		t.Errorf("expected scale clamped to 3.00 for input 5.0, got:\n%s", css)
	}
}

func TestBuildCSS_DarkInputsUsePaletteColors(t *testing.T) {
	p := coretheme.DefaultDarkPalette()
	css := BuildCSS(p, 1.0)

	if !strings.Contains(css, "entry, passwordentry, searchentry, textview") {
		t.Fatalf("expected input styling selector in CSS")
	}
	if !strings.Contains(css, "--glsbw-bg-input:") {
		t.Fatalf("expected input background variable in CSS")
	}
	if !strings.Contains(css, "background-color: var(--glsbw-bg-input)") {
		t.Fatalf("expected inputs to use palette-derived background variable")
	}
	if !strings.Contains(css, p.Bg) || !strings.Contains(css, p.Fg) {
		t.Fatalf("expected palette colors in CSS")
	}
}

func TestBuildCSS_DerivesAccentEffectsFromPalette(t *testing.T) {
	p := coretheme.DefaultDarkPalette()
	p.Accent = "#336699"
	p.RowSelected = "rgba(51, 102, 153, 0.10)"
	css := BuildCSS(p, 1.0)

	for _, expected := range []string{
		"--glsbw-accent-glow: rgba(51, 102, 153, 0.08)",
		"--glsbw-accent-hover: rgba(51, 102, 153, 0.06)",
		"--glsbw-accent-focus: rgba(51, 102, 153, 0.30)",
		"box-shadow: 0 8px 32px rgba(0, 0, 0, 0.50), 0 0 16px var(--glsbw-accent-glow)",
	} {
		if !strings.Contains(css, expected) {
			t.Errorf("expected %q in CSS", expected)
		}
	}
	if strings.Contains(css, "rgba(245, 158, 11") {
		t.Fatalf("expected CSS not to hardcode default accent rgba values")
	}
}

func TestBuildCSS_IncludesStatusColorVariables(t *testing.T) {
	p := coretheme.DefaultDarkPalette()
	css := BuildCSS(p, 1.0)

	for _, expected := range []string{
		p.StatusOK,
		p.StatusPending,
		p.StatusWarning,
		p.StatusConflict,
		p.StatusDanger,
	} {
		if !strings.Contains(css, expected) {
			t.Errorf("expected status color %s in CSS", expected)
		}
	}
}

// TestBuildCSS_IncludesStatusSelectors is intentionally removed as a duplicate.
// The status selectors (.glsbw-status, .glsbw-conflict, .glsbw-error) are
// already covered by TestBuildCSS_DefaultDarkPalette_Scale1_2.
