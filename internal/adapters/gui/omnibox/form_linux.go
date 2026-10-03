//go:build linux && !nogtk

package omnibox

import (
	gtklib "github.com/bnema/puregotk/v4/gtk"
)

// formWidgets maps one FormSession to the GTK widgets that edit it. It is
// created by showForm and only touched on the GTK main thread.
type formWidgets struct {
	session      *FormSession
	entries      map[FieldKey]*gtklib.Entry
	initialFocus *gtklib.Entry
	saveBtn      *gtklib.Button
	errorLabel   *gtklib.Label
}

// showForm builds the form widgets for the session, shows the form panel, and
// focuses the first field. Field set, order, labels, and masking come from
// FormFields; this function only translates them to widgets.
func (v *View) showForm(session *FormSession) {
	// Clear existing children and dynamic callbacks.
	for {
		child := v.formBox.GetFirstChild()
		if child == nil || child.Ptr == 0 {
			break
		}
		v.formBox.Remove(child)
	}
	v.resetDynamicCallbacks()

	ui := &formWidgets{session: session, entries: map[FieldKey]*gtklib.Entry{}}
	v.formUI = ui

	// Back button
	backBtn := gtklib.NewButtonWithLabel("← Back")
	backClickedCb := func(_ gtklib.Button) {
		v.run(func(c *Controller) []Effect { return c.Back() })
	}
	handler := backBtn.ConnectClicked(&backClickedCb)
	v.retainDynamic(&backBtn.Object, handler, backClickedCb)
	v.formBox.Append(&backBtn.Widget)

	// Scrollable content area
	uiScale := 1.0
	if cfg := v.service.Config(); cfg != nil {
		uiScale = cfg.Appearance.UIScale
	}
	contentHeight := ItemFormContentHeight(session.Item.Type, uiScale)
	scrollWin := gtklib.NewScrolledWindow()
	scrollWin.SetPolicy(gtklib.PolicyNeverValue, gtklib.PolicyAutomaticValue)
	scrollWin.SetMinContentHeight(contentHeight)
	scrollWin.SetMaxContentHeight(contentHeight)
	scrollWin.SetPropagateNaturalHeight(true)
	scrollWin.SetPropagateNaturalWidth(false)
	scrollWin.SetMaxContentWidth(defaultOmniboxWidth)
	formContent := gtklib.NewBox(gtklib.OrientationVerticalValue, 4)
	scrollWin.SetChild(&formContent.Widget)
	v.formBox.Append(&scrollWin.Widget)

	for i, field := range session.Fields {
		label := field.Label
		fieldLabel := gtklib.NewLabel(&label)
		formContent.Append(&fieldLabel.Widget)

		entry := gtklib.NewEntry()
		entry.SetText(session.Value(field.Key))
		if field.Secret {
			entry.SetVisibility(false)
		}
		ui.entries[field.Key] = entry
		if i == 0 {
			ui.initialFocus = entry
		}

		if field.Key == FieldPass {
			v.appendPasswordRow(formContent, entry)
			activateCb := func(_ gtklib.Entry) { v.submitForm() }
			handler := entry.ConnectActivate(&activateCb)
			v.retainDynamic(&entry.Object, handler, activateCb)
			continue
		}
		formContent.Append(&entry.Widget)
	}

	// Form-local errors stay visible in form mode and do not rebuild the form,
	// so invalid submissions preserve typed values and focus.
	formErrorText := ""
	ui.errorLabel = gtklib.NewLabel(&formErrorText)
	ui.errorLabel.GetStyleContext().AddClass("glsbw-error")
	ui.errorLabel.SetVisible(false)
	formContent.Append(&ui.errorLabel.Widget)

	ui.saveBtn = gtklib.NewButtonWithLabel("Save")
	saveCb := func(_ gtklib.Button) { v.submitForm() }
	saveHandler := ui.saveBtn.ConnectClicked(&saveCb)
	v.retainDynamic(&ui.saveBtn.Object, saveHandler, saveCb)
	formContent.Append(&ui.saveBtn.Widget)

	v.render()
	v.updateTabStyles()
	if ui.initialFocus != nil {
		ui.initialFocus.GrabFocus()
		return
	}
	v.formBox.GrabFocus()
}

// appendPasswordRow places the password entry next to a button that refills it
// from the generator settings.
func (v *View) appendPasswordRow(formContent *gtklib.Box, pwEntry *gtklib.Entry) {
	passwordRow := gtklib.NewBox(gtklib.OrientationHorizontalValue, 6)
	pwEntry.SetHexpand(true)
	passwordRow.Append(&pwEntry.Widget)
	refreshBtn := gtklib.NewButtonWithLabel("↻")
	refreshTooltip := "Regenerate password from Gen tab settings"
	refreshBtn.SetTooltipText(&refreshTooltip)
	refreshCb := func(_ gtklib.Button) {
		password, err := v.generatePasswordFromCurrentOptions()
		if err != nil {
			v.mu.Lock()
			v.ctrl.State.SetStatus(Status{Text: err.Error(), Error: err.Error()})
			v.mu.Unlock()
			v.renderStatus()
			return
		}
		pwEntry.SetText(password)
		v.mu.Lock()
		v.ctrl.State.SetStatus(Status{Text: "Generated password refreshed"})
		v.mu.Unlock()
		v.renderStatus()
	}
	handler := refreshBtn.ConnectClicked(&refreshCb)
	v.retainDynamic(&refreshBtn.Object, handler, refreshCb)
	passwordRow.Append(&refreshBtn.Widget)
	formContent.Append(&passwordRow.Widget)
}

// submitForm reads every field widget into a key→text map and hands it to the
// controller, which validates, builds the item, and starts the save.
func (v *View) submitForm() {
	ui := v.formUI
	if ui == nil {
		return
	}
	values := make(map[FieldKey]string, len(ui.entries))
	for key, entry := range ui.entries {
		values[key] = entry.GetText()
	}
	v.run(func(c *Controller) []Effect { return c.SubmitForm(ui.session, values) })
}

func (v *View) setFormError(session *FormSession, text string) {
	ui := v.formUI
	if ui == nil || ui.session != session {
		return
	}
	ui.errorLabel.SetText(text)
	ui.errorLabel.SetVisible(text != "")
}

func (v *View) setFormSaving(session *FormSession, saving bool) {
	ui := v.formUI
	if ui == nil || ui.session != session {
		return
	}
	ui.saveBtn.SetSensitive(!saving)
}
