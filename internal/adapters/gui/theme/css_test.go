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
	if !strings.Contains(css, "#175ddc") {
		t.Errorf("expected #175ddc accent in CSS")
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
	if !strings.Contains(css, ".glsbw-row") {
		t.Errorf("expected .glsbw-row selector")
	}
	if !strings.Contains(css, "entry, passwordentry, searchentry, textview") {
		t.Errorf("expected dark input selectors")
	}
	if !strings.Contains(css, ".glsbw-title") {
		t.Errorf("expected .glsbw-title selector")
	}
	if !strings.Contains(css, ".glsbw-subtitle") {
		t.Errorf("expected .glsbw-subtitle selector")
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
	if !strings.Contains(css, "background-color: var(--glsbw-bg)") {
		t.Fatalf("expected inputs to use dark background variable")
	}
	if !strings.Contains(css, p.Bg) || !strings.Contains(css, p.Fg) {
		t.Fatalf("expected palette colors in CSS")
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
