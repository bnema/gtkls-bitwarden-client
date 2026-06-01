package theme

import (
	"strings"
	"testing"

	coretheme "github.com/bnema/gtkls-bitwarden-client/internal/core/theme"
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
	if !strings.Contains(css, "spinbutton.glsbw-spin") {
		t.Errorf("expected themed spinbutton selector")
	}
	if !strings.Contains(css, "spinbutton.glsbw-spin button") {
		t.Errorf("expected themed spinbutton button selector")
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
	if !strings.Contains(css, ".glsbw-detail-title") {
		t.Errorf("expected .glsbw-detail-title selector")
	}
	if !strings.Contains(css, ".glsbw-pin-unlock") {
		t.Errorf("expected .glsbw-pin-unlock selector")
	}
	if !strings.Contains(css, "entry.glsbw-pin-entry") {
		t.Errorf("expected large PIN entry selector")
	}
	if !strings.Contains(css, "--glsbw-surface:") {
		t.Errorf("expected derived surface variable")
	}
	if !strings.Contains(css, "--glsbw-bg-search:") {
		t.Errorf("expected derived search input background variable")
	}
	if !strings.Contains(cssBlock(css, ".glsbw-search"), "background-color: var(--glsbw-bg-search)") {
		t.Errorf("expected search input to use its inset background variable")
	}
	if !strings.Contains(css, "--glsbw-focus:") {
		t.Errorf("expected focus color variable")
	}
	if !strings.Contains(css, "border-left: 3px solid transparent") {
		t.Errorf("expected row selection rail styling")
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
	if !strings.Contains(css, "spinbutton.glsbw-spin text") {
		t.Fatalf("expected spinbutton text styling selector in CSS")
	}
	spinButtonBlock := cssBlock(css, "spinbutton.glsbw-spin button")
	if spinButtonBlock == "" {
		t.Fatalf("expected spinbutton.glsbw-spin button block in CSS")
	}
	for _, expected := range []string{
		"background-color: transparent",
		"border: none",
		"text-shadow: none",
	} {
		if !strings.Contains(spinButtonBlock, expected) {
			t.Fatalf("expected %q in spinbutton button block", expected)
		}
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
	p.Focus = "#66ccff"
	p.StatusPending = "#ffd100"
	p.RowSelected = "rgba(51, 102, 153, 0.10)"
	css := BuildCSS(p, 1.0)

	for _, expected := range []string{
		"--glsbw-accent-hover: rgba(51, 102, 153, 0.10)",
		"--glsbw-focus: #66ccff",
		"--glsbw-focus-ring: rgba(102, 204, 255, 0.28)",
	} {
		if !strings.Contains(css, expected) {
			t.Errorf("expected %q in CSS", expected)
		}
	}
	if !strings.Contains(cssBlock(css, ".glsbw-omnibox"), "box-shadow: none") {
		t.Fatalf("expected omnibox shell not to draw a drop shadow")
	}
	if strings.Contains(css, "rgba(23, 93, 220") {
		t.Fatalf("expected CSS not to hardcode default Bitwarden accent rgba values")
	}
}

func TestBuildCSS_FocusFallsBackToAccent(t *testing.T) {
	p := coretheme.DefaultDarkPalette()
	p.Accent = "#4477aa"
	p.Focus = ""
	css := BuildCSS(p, 1.0)

	for _, expected := range []string{
		"--glsbw-focus: #4477aa",
		"--glsbw-focus-ring: rgba(68, 119, 170, 0.28)",
	} {
		if !strings.Contains(css, expected) {
			t.Fatalf("expected %q in CSS", expected)
		}
	}
}

func TestMixHex_ClampsWeight(t *testing.T) {
	if got := mixHex("#000000", "#ffffff", -1); got != "#000000" {
		t.Fatalf("expected low clamp to preserve source, got %s", got)
	}
	if got := mixHex("#000000", "#ffffff", 2); got != "#ffffff" {
		t.Fatalf("expected high clamp to use target, got %s", got)
	}
}

func TestRGBAHex_SupportsShortHex(t *testing.T) {
	if got := rgbaHex("#abc", 0.5); got != "rgba(170, 187, 204, 0.50)" {
		t.Fatalf("expected short hex to expand correctly, got %s", got)
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

func cssBlock(css, selector string) string {
	needle := selector + " {"
	start := strings.Index(css, needle)
	if start == -1 {
		return ""
	}
	rest := css[start:]
	end := strings.Index(rest, "}\n")
	if end == -1 {
		return rest
	}
	return rest[:end+1]
}

// TestBuildCSS_IncludesStatusSelectors is intentionally removed as a duplicate.
// The status selectors (.glsbw-status, .glsbw-conflict, .glsbw-error) are
// already covered by TestBuildCSS_DefaultDarkPalette_Scale1_2.
