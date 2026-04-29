//go:build linux && !nogtk

package omnibox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bnema/puregotk/v4/gdk"
	gtklib "github.com/bnema/puregotk/v4/gtk"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/ports/in"
)

// View is the GTK omnibox UI. It manages the unlock, search, detail, and form
// views inside a single root box.
type View struct {
	Root *gtklib.Box

	service in.AppService
	state   State
	quit    func()
	retain  func(interface{})

	// Widgets
	unlockBox     *gtklib.Box
	emailEntry    *gtklib.Entry
	passwordEntry *gtklib.Entry
	errorLabel    *gtklib.Label
	searchBox     *gtklib.Box
	searchEntry   *gtklib.Entry
	rowsBox       *gtklib.Box
	detailBox     *gtklib.Box
	formBox       *gtklib.Box
	statusLabel   *gtklib.Label
	statusBox     *gtklib.Box

	mu sync.Mutex
}

// New creates a new View, builds all GTK widgets, and starts the event listener.
func New(ctx context.Context, service in.AppService, quit func(), retainFn func(interface{})) *View {
	v := &View{
		service: service,
		state:   NewState(),
		quit:    quit,
		retain:  retainFn,
	}

	v.buildUI()
	v.showUnlock()

	// Subscribe to service events.
	go v.eventLoop(ctx)

	return v
}

// buildUI creates all GTK widgets.
func (v *View) buildUI() {
	v.Root = gtklib.NewBox(gtklib.OrientationVerticalValue, 0)
	styleCtx := v.Root.GetStyleContext()
	styleCtx.AddClass("glsbw-omnibox")

	// --- Unlock view ---
	v.unlockBox = gtklib.NewBox(gtklib.OrientationVerticalValue, 4)

	// Email entry
	v.emailEntry = gtklib.NewEntry()
	placeholderEmail := "Email"
	v.emailEntry.SetPlaceholderText(&placeholderEmail)
	if cfg := v.service.Config(); cfg != nil {
		v.emailEntry.SetText(cfg.Bitwarden.Email)
	}
	v.unlockBox.Append(&v.emailEntry.Widget)

	// Password entry
	v.passwordEntry = gtklib.NewEntry()
	placeholderPass := "Master password"
	v.passwordEntry.SetPlaceholderText(&placeholderPass)
	v.passwordEntry.SetVisibility(false)
	v.unlockBox.Append(&v.passwordEntry.Widget)

	// Error label (initially hidden/empty)
	errText := ""
	v.errorLabel = gtklib.NewLabel(&errText)
	v.errorLabel.SetVisible(false)
	v.unlockBox.Append(&v.errorLabel.Widget)

	// Unlock action on password Enter.
	activateCb := func(_ gtklib.Entry) {
		v.doUnlock(context.Background())
	}
	v.retain(activateCb)
	v.passwordEntry.ConnectActivate(&activateCb)

	v.Root.Append(&v.unlockBox.Widget)

	// --- Search view (initially hidden) ---
	v.searchBox = gtklib.NewBox(gtklib.OrientationVerticalValue, 4)

	searchPlaceholder := "Search vault…"
	v.searchEntry = gtklib.NewEntry()
	v.searchEntry.SetPlaceholderText(&searchPlaceholder)
	v.searchBox.Append(&v.searchEntry.Widget)

	// Rows container
	scrollWin := gtklib.NewScrolledWindow()
	scrollWin.SetVexpand(true)
	v.rowsBox = gtklib.NewBox(gtklib.OrientationVerticalValue, 0)
	scrollWin.SetChild(&v.rowsBox.Widget)
	v.searchBox.Append(&scrollWin.Widget)

	// Status label
	statusText := ""
	v.statusLabel = gtklib.NewLabel(&statusText)
	v.statusBox = gtklib.NewBox(gtklib.OrientationHorizontalValue, 0)
	v.statusBox.Append(&v.statusLabel.Widget)
	v.searchBox.Append(&v.statusBox.Widget)

	v.Root.Append(&v.searchBox.Widget)

	// Search entry: Enter triggers primary action on selected row.
	searchActivateCb := func(_ gtklib.Entry) {
		v.doPrimaryAction()
	}
	v.retain(searchActivateCb)
	v.searchEntry.ConnectActivate(&searchActivateCb)

	// Search on key release with debounce.
	searchReleasedCb := func(_ gtklib.EventControllerKey, keyval uint, _ uint, _ gdk.ModifierType) {
		kv := int(keyval)
		if isSearchKey(kv) {
			v.debounceSearch()
		}
	}
	v.retain(searchReleasedCb)
	ctrl := gtklib.NewEventControllerKey()
	ctrl.ConnectKeyReleased(&searchReleasedCb)
	v.searchBox.AddController(&ctrl.EventController)

	// --- Detail view (initially hidden) ---
	v.detailBox = gtklib.NewBox(gtklib.OrientationVerticalValue, 4)
	v.Root.Append(&v.detailBox.Widget)

	// --- Form view (initially hidden) ---
	v.formBox = gtklib.NewBox(gtklib.OrientationVerticalValue, 4)
	formStatusText := "Edit form not wired yet"
	formStatusLabel := gtklib.NewLabel(&formStatusText)
	v.formBox.Append(&formStatusLabel.Widget)
	formBackBtn := gtklib.NewButtonWithLabel("← Back")
	formBackClickedCb := func(_ gtklib.Button) {
		v.mu.Lock()
		v.state.Back()
		v.mu.Unlock()
		idleAddOnce(func() { v.render() })
	}
	v.retain(formBackClickedCb)
	formBackBtn.ConnectClicked(&formBackClickedCb)
	v.formBox.Append(&formBackBtn.Widget)

	v.Root.Append(&v.formBox.Widget)
}

// isSearchKey returns true if the keyval is a printable/search character.
func isSearchKey(kv int) bool {
	return kv == gdk.KEY_BackSpace || kv == gdk.KEY_Delete ||
		(kv >= gdk.KEY_0 && kv <= gdk.KEY_9) ||
		(kv >= gdk.KEY_a && kv <= gdk.KEY_z) ||
		(kv >= gdk.KEY_A && kv <= gdk.KEY_Z) ||
		kv == gdk.KEY_space || kv == gdk.KEY_Tab ||
		kv == gdk.KEY_period || kv == gdk.KEY_comma ||
		kv == gdk.KEY_slash || kv == gdk.KEY_backslash ||
		kv == gdk.KEY_minus || kv == gdk.KEY_equal ||
		kv == gdk.KEY_bracketleft || kv == gdk.KEY_bracketright ||
		kv == gdk.KEY_semicolon || kv == gdk.KEY_apostrophe ||
		kv == gdk.KEY_grave || kv == gdk.KEY_at ||
		kv == gdk.KEY_numbersign || kv == gdk.KEY_dollar ||
		kv == gdk.KEY_percent || kv == gdk.KEY_asciicircum ||
		kv == gdk.KEY_ampersand || kv == gdk.KEY_asterisk ||
		kv == gdk.KEY_parenleft || kv == gdk.KEY_parenright ||
		kv == gdk.KEY_underscore || kv == gdk.KEY_plus ||
		kv == gdk.KEY_braceleft || kv == gdk.KEY_braceright ||
		kv == gdk.KEY_bar || kv == gdk.KEY_colon ||
		kv == gdk.KEY_quotedbl || kv == gdk.KEY_less ||
		kv == gdk.KEY_greater || kv == gdk.KEY_question ||
		kv == gdk.KEY_asciitilde
}

// AttachKeyController attaches a key controller to the given window for
// keyboard navigation.
func (v *View) AttachKeyController(window *gtklib.Window) {
	ctrl := gtklib.NewEventControllerKey()
	pressedCb := func(_ gtklib.EventControllerKey, keyval uint, _ uint, mod gdk.ModifierType) bool {
		kv := int(keyval)
		v.mu.Lock()
		defer v.mu.Unlock()

		switch v.state.Mode {
		case ModeUnlock:
			if kv == gdk.KEY_Escape {
				idleAddOnce(v.quit)
				return true
			}
		case ModeSearch:
			switch kv {
			case gdk.KEY_Up:
				v.state.Move(-1)
				idleAddOnce(func() { v.renderRows() })
				return true
			case gdk.KEY_Down:
				v.state.Move(1)
				idleAddOnce(func() { v.renderRows() })
				return true
			case gdk.KEY_Return, gdk.KEY_KP_Enter:
				if mod&gdk.ControlMaskValue != 0 {
					v.state.OpenDetail()
					idleAddOnce(func() { v.render() })
					return true
				}
				return false
			case gdk.KEY_Escape:
				idleAddOnce(v.quit)
				return true
			}
		case ModeDetail:
			if kv == gdk.KEY_Escape || kv == gdk.KEY_BackSpace {
				v.state.Back()
				idleAddOnce(func() { v.render() })
				return true
			}
		case ModeForm:
			if kv == gdk.KEY_Escape || kv == gdk.KEY_BackSpace {
				v.state.Back()
				idleAddOnce(func() { v.render() })
				return true
			}
		}
		return false
	}
	v.retain(pressedCb)
	ctrl.ConnectKeyPressed(&pressedCb)
	window.AddController(&ctrl.EventController)
}

// GrabFocus focuses the appropriate entry for the current mode.
func (v *View) GrabFocus() {
	v.mu.Lock()
	defer v.mu.Unlock()

	switch v.state.Mode {
	case ModeUnlock:
		if v.emailEntry.GetText() == "" {
			v.emailEntry.GrabFocus()
		} else {
			v.passwordEntry.GrabFocus()
		}
	case ModeSearch:
		v.searchEntry.GrabFocus()
	case ModeDetail:
		v.detailBox.GrabFocus()
	case ModeForm:
		v.formBox.GrabFocus()
	}
}

// --- Internal methods ---

// showUnlock makes the unlock view visible and hides others.
func (v *View) showUnlock() {
	v.unlockBox.SetVisible(true)
	v.searchBox.SetVisible(false)
	v.detailBox.SetVisible(false)
	v.formBox.SetVisible(false)
	v.state.Mode = ModeUnlock
}

// doUnlock runs the unlock flow.
func (v *View) doUnlock(ctx context.Context) {
	email := v.emailEntry.GetText()
	password := v.passwordEntry.GetText()

	if email == "" || password == "" {
		v.showError("Email and password are required")
		return
	}

	v.showError("")

	go func() {
		unlockErr := v.service.Unlock(ctx, email, password)
		if unlockErr != nil {
			v.showError(unlockErr.Error())
			return
		}

		idleAddOnce(func() {
			v.passwordEntry.SetText("")

			v.mu.Lock()
			v.state.Mode = ModeSearch
			v.state.Error = ""
			v.unlockBox.SetVisible(false)
			v.searchBox.SetVisible(true)
			v.detailBox.SetVisible(false)
			v.formBox.SetVisible(false)
			v.mu.Unlock()

			v.searchEntry.GrabFocus()
			v.loadAllItems()
		})
	}()
}

// loadAllItems fetches items in a goroutine and updates rows.
func (v *View) loadAllItems() {
	go func() {
		items, err := v.service.Items(context.Background())
		if err != nil {
			idleAddOnce(func() {
				v.mu.Lock()
				v.state.Error = fmt.Sprintf("Failed to load items: %v", err)
				v.mu.Unlock()
				v.render()
			})
			return
		}
		rows := RowsFromItems(items)
		idleAddOnce(func() {
			v.mu.Lock()
			v.state.SetRows(rows)
			v.mu.Unlock()
			v.renderRows()
		})
	}()
}

// searchLock serialises concurrent searches.
var searchLock sync.Mutex

// searchTimer is the debounce timer for search input.
var searchTimer *time.Timer

// debounceSearch cancels any pending search and schedules a new one.
func (v *View) debounceSearch() {
	if searchTimer != nil {
		searchTimer.Stop()
	}
	searchTimer = time.AfterFunc(150*time.Millisecond, func() {
		query := ""
		idleAddOnce(func() {
			v.mu.Lock()
			query = v.searchEntry.GetText()
			v.mu.Unlock()
		})
		if query == "" {
			v.loadAllItems()
			return
		}
		v.doSearch(query)
	})
}

// doSearch runs a search query.
func (v *View) doSearch(query string) {
	if !searchLock.TryLock() {
		return
	}
	go func() {
		defer searchLock.Unlock()
		results, err := v.service.Search(context.Background(), query, 50)
		if err != nil {
			return
		}
		rows := RowsFromScored(results)
		idleAddOnce(func() {
			v.mu.Lock()
			v.state.SetRows(rows)
			v.mu.Unlock()
			v.renderRows()
		})
	}()
}

// doPrimaryAction performs the primary action on the selected row.
func (v *View) doPrimaryAction() {
	v.mu.Lock()
	row, ok := v.state.SelectedRow()
	if !ok {
		v.mu.Unlock()
		return
	}
	action := PrimaryActionFor(row, v.service.Config())
	v.mu.Unlock()

	switch action {
	case ActionCopyPassword:
		v.mu.Lock()
		v.state.SetStatus(Status{Text: "Password copied"})
		v.mu.Unlock()
		v.renderStatus()
	case ActionCopyUsername:
		v.mu.Lock()
		v.state.SetStatus(Status{Text: "Username copied"})
		v.mu.Unlock()
		v.renderStatus()
	default:
		v.mu.Lock()
		v.state.OpenDetail()
		detailID := v.state.DetailID
		v.mu.Unlock()
		v.loadDetail(detailID)
		idleAddOnce(func() { v.render() })
	}
}

// loadDetail fetches a single item and renders the detail view.
func (v *View) loadDetail(id string) {
	go func() {
		item, err := v.service.Get(context.Background(), id)
		if err != nil {
			idleAddOnce(func() {
				v.mu.Lock()
				v.state.Error = fmt.Sprintf("Failed to load detail: %v", err)
				v.mu.Unlock()
				v.render()
			})
			return
		}
		detail := DetailFromItem(item)
		idleAddOnce(func() {
			v.renderDetail(detail)
		})
	}()
}

// showError sets the error label text and visibility.
func (v *View) showError(msg string) {
	idleAddOnce(func() {
		if msg == "" {
			v.errorLabel.SetVisible(false)
			v.errorLabel.SetText("")
		} else {
			v.errorLabel.SetText(msg)
			v.errorLabel.SetVisible(true)
		}
	})
}

// render updates the visibility of all panels based on current mode.
func (v *View) render() {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.unlockBox.SetVisible(v.state.Mode == ModeUnlock)
	v.searchBox.SetVisible(v.state.Mode == ModeSearch)
	v.detailBox.SetVisible(v.state.Mode == ModeDetail)
	v.formBox.SetVisible(v.state.Mode == ModeForm)
	v.renderStatus()
}

// renderRows clears and rebuilds the rows box.
func (v *View) renderRows() {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Clear existing children.
	for {
		child := v.rowsBox.GetFirstChild()
		if child == nil || child.Ptr == 0 {
			break
		}
		v.rowsBox.Remove(child)
	}

	for i, row := range v.state.Rows {
		rowWidget := v.buildRowWidget(row, i == v.state.Selected)
		v.rowsBox.Append(&rowWidget.Widget)
	}
}

// buildRowWidget creates a single row widget.
func (v *View) buildRowWidget(row Row, selected bool) *gtklib.Box {
	hbox := gtklib.NewBox(gtklib.OrientationHorizontalValue, 4)

	title := row.Title
	if subtitle := row.Subtitle; subtitle != "" {
		title = title + " — " + subtitle
	}
	label := gtklib.NewLabel(&title)
	label.SetHalign(gtklib.AlignStartValue)
	label.SetXalign(0)
	hbox.Append(&label.Widget)

	if row.Badge != "" {
		badge := gtklib.NewLabel(&row.Badge)
		badge.SetHalign(gtklib.AlignEndValue)
		hbox.Append(&badge.Widget)
	}

	if selected {
		styleCtx := hbox.GetStyleContext()
		styleCtx.AddClass("glsbw-selected")
	}

	return hbox
}

// renderDetail populates the detail box with safe item fields.
func (v *View) renderDetail(detail Detail) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Remove all existing children.
	for {
		child := v.detailBox.GetFirstChild()
		if child == nil || child.Ptr == 0 {
			break
		}
		v.detailBox.Remove(child)
	}

	// Back button
	backBtn := gtklib.NewButtonWithLabel("← Back")
	backClickedCb := func(_ gtklib.Button) {
		v.mu.Lock()
		v.state.Back()
		v.mu.Unlock()
		idleAddOnce(func() { v.render() })
	}
	v.retain(backClickedCb)
	backBtn.ConnectClicked(&backClickedCb)
	v.detailBox.Append(&backBtn.Widget)

	// Title
	titleLabel := gtklib.NewLabel(&detail.Title)
	titleLabel.GetStyleContext().AddClass("glsbw-detail-title")
	v.detailBox.Append(&titleLabel.Widget)

	// Type
	typeStr := detail.Type
	typeLabel := gtklib.NewLabel(&typeStr)
	v.detailBox.Append(&typeLabel.Widget)

	// Username (safe)
	if detail.Username != "" {
		uStr := "Username: " + detail.Username
		uLabel := gtklib.NewLabel(&uStr)
		v.detailBox.Append(&uLabel.Widget)
	}

	// URI
	if detail.URI != "" {
		uriStr := "URI: " + detail.URI
		uriLabel := gtklib.NewLabel(&uriStr)
		v.detailBox.Append(&uriLabel.Widget)
	}

	// Secret presence indicators (safe booleans only)
	if detail.PasswordPresent {
		pwStr := "✓ Password stored"
		pwLabel := gtklib.NewLabel(&pwStr)
		v.detailBox.Append(&pwLabel.Widget)
	}
	if detail.TOTPPresent {
		totpStr := "✓ TOTP stored"
		totpLabel := gtklib.NewLabel(&totpStr)
		v.detailBox.Append(&totpLabel.Widget)
	}

	// Card info (safe)
	if detail.CardBrand != "" {
		cardStr := "Card: " + detail.CardBrand
		if detail.CardLast4 != "" {
			cardStr = "Card: " + detail.CardBrand + " •••• " + detail.CardLast4
		}
		cardLabel := gtklib.NewLabel(&cardStr)
		v.detailBox.Append(&cardLabel.Widget)
	}

	// Identity name
	if detail.IdentityName != "" {
		idStr := "Identity: " + detail.IdentityName
		idLabel := gtklib.NewLabel(&idStr)
		v.detailBox.Append(&idLabel.Widget)
	}

	// Notes present indicator
	if detail.NotesPresent {
		notesStr := "✓ Notes present"
		notesLabel := gtklib.NewLabel(&notesStr)
		v.detailBox.Append(&notesLabel.Widget)
	}

	// Attachments list
	if len(detail.Attachments) > 0 {
		attStr := "Attachments:"
		attLabel := gtklib.NewLabel(&attStr)
		v.detailBox.Append(&attLabel.Widget)
		for _, fname := range detail.Attachments {
			fStr := "  " + fname
			fLabel := gtklib.NewLabel(&fStr)
			v.detailBox.Append(&fLabel.Widget)
		}
	}

	// Conflict/Pending/Deleted badges
	if detail.Conflict {
		cStr := "⚠ Conflict"
		cLabel := gtklib.NewLabel(&cStr)
		v.detailBox.Append(&cLabel.Widget)
	}
	if detail.Pending {
		pStr := "⏳ Pending"
		pLabel := gtklib.NewLabel(&pStr)
		v.detailBox.Append(&pLabel.Widget)
	}
	if detail.Deleted {
		dStr := "🗑 Deleted"
		dLabel := gtklib.NewLabel(&dStr)
		v.detailBox.Append(&dLabel.Widget)
	}

	// Trash/Restore/Delete buttons
	if !detail.Deleted {
		trashBtn := gtklib.NewButtonWithLabel("Trash")
		trashCb := func(_ gtklib.Button) {
			go func() {
				if err := v.service.Trash(context.Background(), detail.ID); err != nil {
					v.showError(err.Error())
					return
				}
				idleAddOnce(func() {
					v.mu.Lock()
					v.state.Back()
					v.mu.Unlock()
					v.render()
				})
			}()
		}
		v.retain(trashCb)
		trashBtn.ConnectClicked(&trashCb)
		v.detailBox.Append(&trashBtn.Widget)
	} else {
		restoreBtn := gtklib.NewButtonWithLabel("Restore")
		restoreCb := func(_ gtklib.Button) {
			go func() {
				if _, err := v.service.Restore(context.Background(), detail.ID); err != nil {
					v.showError(err.Error())
					return
				}
				idleAddOnce(func() {
					v.mu.Lock()
					v.state.Back()
					v.mu.Unlock()
					v.render()
				})
			}()
		}
		v.retain(restoreCb)
		restoreBtn.ConnectClicked(&restoreCb)
		v.detailBox.Append(&restoreBtn.Widget)

		deleteBtn := gtklib.NewButtonWithLabel("Delete permanently")
		deleteCb := func(_ gtklib.Button) {
			go func() {
				if err := v.service.Delete(context.Background(), detail.ID); err != nil {
					v.showError(err.Error())
					return
				}
				idleAddOnce(func() {
					v.mu.Lock()
					v.state.Back()
					v.mu.Unlock()
					v.render()
				})
			}()
		}
		v.retain(deleteCb)
		deleteBtn.ConnectClicked(&deleteCb)
		v.detailBox.Append(&deleteBtn.Widget)
	}

	v.detailBox.SetVisible(true)
}

// renderStatus updates the status label.
func (v *View) renderStatus() {
	text := v.state.Status.Text
	if text == "" {
		v.statusBox.SetVisible(false)
	} else {
		v.statusLabel.SetText(text)
		v.statusBox.SetVisible(true)
	}
}

// eventLoop listens for service events and updates status.
func (v *View) eventLoop(ctx context.Context) {
	eventCh := v.service.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-eventCh:
			if !ok {
				return
			}
			st := StatusFromEvent(evt)
			idleAddOnce(func() {
				v.mu.Lock()
				v.state.SetStatus(st)
				v.mu.Unlock()
				v.renderStatus()
			})
		}
	}
}
