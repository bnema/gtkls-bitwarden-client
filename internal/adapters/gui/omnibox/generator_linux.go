//go:build linux && !nogtk

package omnibox

import (
	"time"

	gtklib "github.com/bnema/puregotk/v4/gtk"

	"github.com/bnema/gtkls-bitwarden-client/internal/core/passwordgen"
)

func (v *View) buildGeneratorUI() {
	defaults := passwordgen.DefaultOptions()

	v.generatorBox = gtklib.NewBox(gtklib.OrientationVerticalValue, 8)

	backBtn := gtklib.NewButtonWithLabel("← Back")
	backCb := func(_ gtklib.Button) {
		v.mu.Lock()
		v.state.Back()
		v.mu.Unlock()
		v.render()
		v.GrabFocus()
	}
	v.retain(backCb)
	backBtn.ConnectClicked(&backCb)
	v.generatorBox.Append(&backBtn.Widget)

	titleText := "Generate password"
	titleLabel := gtklib.NewLabel(&titleText)
	titleLabel.SetHalign(gtklib.AlignStartValue)
	v.generatorBox.Append(&titleLabel.Widget)

	lengthText := "Length"
	lengthLabel := gtklib.NewLabel(&lengthText)
	lengthLabel.SetHalign(gtklib.AlignStartValue)
	v.generatorBox.Append(&lengthLabel.Widget)

	v.generatorLengthSpin = gtklib.NewSpinButtonWithRange(4, 128, 1)
	v.generatorLengthSpin.GetStyleContext().AddClass("glsbw-spin")
	v.generatorLengthSpin.SetNumeric(true)
	v.generatorLengthSpin.SetValue(float64(defaults.Length))
	v.generatorBox.Append(&v.generatorLengthSpin.Widget)

	lowerText := "Lowercase (a-z)"
	v.generatorLowerCheck = gtklib.NewCheckButtonWithLabel(&lowerText)
	v.generatorLowerCheck.SetActive(defaults.Lowercase)
	v.generatorBox.Append(&v.generatorLowerCheck.Widget)

	upperText := "Uppercase (A-Z)"
	v.generatorUpperCheck = gtklib.NewCheckButtonWithLabel(&upperText)
	v.generatorUpperCheck.SetActive(defaults.Uppercase)
	v.generatorBox.Append(&v.generatorUpperCheck.Widget)

	numberText := "Numbers (0-9)"
	v.generatorNumberCheck = gtklib.NewCheckButtonWithLabel(&numberText)
	v.generatorNumberCheck.SetActive(defaults.Numbers)
	v.generatorBox.Append(&v.generatorNumberCheck.Widget)

	symbolText := "Symbols (!@#$%^&*)"
	v.generatorSymbolCheck = gtklib.NewCheckButtonWithLabel(&symbolText)
	v.generatorSymbolCheck.SetActive(defaults.Symbols)
	v.generatorBox.Append(&v.generatorSymbolCheck.Widget)

	outputText := "Generated password"
	outputLabel := gtklib.NewLabel(&outputText)
	outputLabel.SetHalign(gtklib.AlignStartValue)
	v.generatorBox.Append(&outputLabel.Widget)

	v.generatorOutput = gtklib.NewEntry()
	v.generatorOutput.SetEditable(false)
	v.generatorBox.Append(&v.generatorOutput.Widget)

	buttons := gtklib.NewBox(gtklib.OrientationHorizontalValue, 8)
	generateBtn := gtklib.NewButtonWithLabel("Generate")
	copyBtn := gtklib.NewButtonWithLabel("Copy to clipboard")
	buttons.Append(&generateBtn.Widget)
	buttons.Append(&copyBtn.Widget)
	v.generatorBox.Append(&buttons.Widget)

	generateCb := func(_ gtklib.Button) {
		v.generatePasswordFromControls()
	}
	copyCb := func(_ gtklib.Button) {
		v.copyGeneratedPassword()
	}
	spinActivateCb := func(_ gtklib.SpinButton) {
		v.generatePasswordFromControls()
	}

	v.retain(generateCb)
	v.retain(copyCb)
	v.retain(spinActivateCb)
	generateBtn.ConnectClicked(&generateCb)
	copyBtn.ConnectClicked(&copyCb)
	v.generatorLengthSpin.ConnectActivate(&spinActivateCb)
}

func (v *View) startPasswordGenerator() {
	v.setMode(ModeGenerator)

	v.render()
	v.updateTabStyles()
	v.GrabFocus()

	if v.generatorOutput != nil && v.generatorOutput.GetText() == "" {
		v.generatePasswordFromControls()
	}
}

func (v *View) generatorOptions() passwordgen.Options {
	return passwordgen.Options{
		Length:    v.generatorLengthSpin.GetValueAsInt(),
		Lowercase: v.generatorLowerCheck.GetActive(),
		Uppercase: v.generatorUpperCheck.GetActive(),
		Numbers:   v.generatorNumberCheck.GetActive(),
		Symbols:   v.generatorSymbolCheck.GetActive(),
	}
}

func (v *View) generatePasswordFromControls() {
	if v.generatorOutput == nil {
		return
	}

	password, err := v.generatePasswordFromCurrentOptions()
	if err != nil {
		v.mu.Lock()
		v.state.SetStatus(Status{Text: err.Error(), Error: err.Error()})
		v.mu.Unlock()
		v.renderStatus()
		return
	}

	v.generatorOutput.SetText(password)
	v.mu.Lock()
	v.state.SetStatus(Status{Text: "Generated password"})
	v.mu.Unlock()
	v.renderStatus()
}

func (v *View) generatePasswordFromCurrentOptions() (string, error) {
	return passwordgen.Generate(v.generatorOptions())
}

func (v *View) copyGeneratedPassword() {
	if v.generatorOutput == nil || v.clipboard == nil {
		v.mu.Lock()
		v.state.SetStatus(Status{Text: genericOperationError, Error: genericOperationError})
		v.mu.Unlock()
		v.renderStatus()
		return
	}

	text := v.generatorOutput.GetText()
	if text == "" {
		v.mu.Lock()
		v.state.SetStatus(Status{Text: "Generate a password first"})
		v.mu.Unlock()
		v.renderStatus()
		return
	}

	ttl := time.Duration(0)
	if cfg := v.service.Config(); cfg != nil {
		ttl = cfg.Actions.ClipboardClearAfter
	}

	go func() {
		if err := v.copyGeneratedPasswordText(text, ttl); err != nil {
			logOverlayError(v.ctx, "copy_generated_password", err)
			idleAddOnce(func() {
				v.mu.Lock()
				v.state.SetStatus(Status{Text: genericOperationError, Error: genericOperationError})
				v.mu.Unlock()
				v.renderStatus()
			})
			return
		}

		idleAddOnce(func() {
			v.mu.Lock()
			v.state.SetStatus(Status{Text: "Password copied"})
			v.mu.Unlock()
			v.renderStatus()
		})
	}()
}

func (v *View) copyGeneratedPasswordText(text string, ttl time.Duration) error {
	return v.clipboard.Set(v.ctx, text, ttl)
}
