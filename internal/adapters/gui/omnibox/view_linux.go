//go:build linux && !nogtk

package omnibox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bnema/puregotk/v4/gdk"
	gobject "github.com/bnema/puregotk/v4/gobject"
	gtklib "github.com/bnema/puregotk/v4/gtk"

	"github.com/bnema/gtk4-layershell-bitwarden/internal/core/vault"
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

	mu          sync.Mutex
	currentItem vault.Item
	searchTimer *time.Timer
	searchLock  sync.Mutex

	dynamicHandlers []dynamicHandler
}

// dynamicHandler tracks a GTK signal connection that must be explicitly
// disconnected from the puregotk/glib registry, not just dropped from a slice.
type dynamicHandler struct {
	obj      *gobject.Object
	handler  uint
	callback interface{}
}

// retainDynamic stores the handler and its owning object so the signal can be
// disconnected later via resetDynamicCallbacks.
func (v *View) retainDynamic(obj *gobject.Object, handler uint, cb interface{}) {
	v.dynamicHandlers = append(v.dynamicHandlers, dynamicHandler{obj: obj, handler: handler, callback: cb})
}

// resetDynamicCallbacks disconnects all tracked dynamic signal handlers from
// the puregotk/glib registry and clears the slice.
func (v *View) resetDynamicCallbacks() {
	for _, h := range v.dynamicHandlers {
		if h.obj != nil && h.handler != 0 {
			h.obj.DisconnectSignal(h.handler)
		}
	}
	v.dynamicHandlers = nil
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
			query := v.searchEntry.GetText()
			v.debounceSearch(query)
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
		mode := v.state.Mode

		handleUnlock := func() bool {
			if kv == gdk.KEY_Escape {
				v.mu.Unlock()
				idleAddOnce(v.quit)
				return true
			}
			v.mu.Unlock()
			return false
		}

		handleSearch := func() bool {
			switch kv {
			case gdk.KEY_Up:
				v.state.Move(-1)
				v.mu.Unlock()
				idleAddOnce(func() { v.renderRows() })
				return true
			case gdk.KEY_Down:
				v.state.Move(1)
				v.mu.Unlock()
				idleAddOnce(func() { v.renderRows() })
				return true
			case gdk.KEY_Return, gdk.KEY_KP_Enter:
				if mod&gdk.ControlMaskValue != 0 {
					v.state.OpenDetail()
					detailID := v.state.DetailID
					v.mu.Unlock()
					v.loadDetail(detailID)
					idleAddOnce(func() { v.render() })
					return true
				}
				v.mu.Unlock()
				return false
			case gdk.KEY_n:
				if mod&gdk.ControlMaskValue != 0 {
					v.currentItem = vault.Item{Type: vault.ItemTypeLogin}
					v.state.Mode = ModeForm
					item := v.currentItem
					v.mu.Unlock()
					idleAddOnce(func() {
						v.renderForm(item)
						v.render()
					})
					return true
				}
				v.mu.Unlock()
				return false
			case gdk.KEY_Escape:
				v.mu.Unlock()
				idleAddOnce(v.quit)
				return true
			default:
				v.mu.Unlock()
				return false
			}
		}

		handleDetail := func() bool {
			if kv == gdk.KEY_Escape || kv == gdk.KEY_BackSpace {
				v.state.Back()
				v.mu.Unlock()
				idleAddOnce(func() { v.render() })
				return true
			}
			v.mu.Unlock()
			return false
		}

		handleForm := func() bool {
			if kv == gdk.KEY_Escape || kv == gdk.KEY_BackSpace {
				v.state.Back()
				v.mu.Unlock()
				idleAddOnce(func() { v.render() })
				return true
			}
			v.mu.Unlock()
			return false
		}

		switch mode {
		case ModeUnlock:
			return handleUnlock()
		case ModeSearch:
			return handleSearch()
		case ModeDetail:
			return handleDetail()
		case ModeForm:
			return handleForm()
		default:
			v.mu.Unlock()
			return false
		}
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

// debounceSearch cancels any pending search and schedules a new one with the
// given query. The query must be read on the GTK thread before calling this.
func (v *View) debounceSearch(query string) {
	v.mu.Lock()
	if v.searchTimer != nil {
		v.searchTimer.Stop()
	}
	v.searchTimer = time.AfterFunc(150*time.Millisecond, func() {
		if query == "" {
			v.loadAllItems()
			return
		}
		v.doSearch(query)
	})
	v.mu.Unlock()
}

// doSearch runs a search query.
func (v *View) doSearch(query string) {
	if !v.searchLock.TryLock() {
		return
	}
	go func() {
		defer v.searchLock.Unlock()
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
		v.mu.Lock()
		v.currentItem = item
		v.mu.Unlock()
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

	// Remove all existing children and clear dynamic callbacks.
	for {
		child := v.detailBox.GetFirstChild()
		if child == nil || child.Ptr == 0 {
			break
		}
		v.detailBox.Remove(child)
	}
	v.resetDynamicCallbacks()

	// Back button
	backBtn := gtklib.NewButtonWithLabel("← Back")
	backClickedCb := func(_ gtklib.Button) {
		v.mu.Lock()
		v.state.Back()
		v.mu.Unlock()
		idleAddOnce(func() { v.render() })
	}
	handler := backBtn.ConnectClicked(&backClickedCb)
	v.retainDynamic(&backBtn.Object, handler, backClickedCb)
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

	// Edit button
	editBtn := gtklib.NewButtonWithLabel("Edit")
	editCb := func(_ gtklib.Button) {
		v.mu.Lock()
		v.state.Mode = ModeForm
		item := v.currentItem
		v.mu.Unlock()
		idleAddOnce(func() {
			v.renderForm(item)
			v.render()
		})
	}
	handler0 := editBtn.ConnectClicked(&editCb)
	v.retainDynamic(&editBtn.Object, handler0, editCb)
	v.detailBox.Append(&editBtn.Widget)

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
		handler := trashBtn.ConnectClicked(&trashCb)
		v.retainDynamic(&trashBtn.Object, handler, trashCb)
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
		handler := restoreBtn.ConnectClicked(&restoreCb)
		v.retainDynamic(&restoreBtn.Object, handler, restoreCb)
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
		handler = deleteBtn.ConnectClicked(&deleteCb)
		v.retainDynamic(&deleteBtn.Object, handler, deleteCb)
		v.detailBox.Append(&deleteBtn.Widget)
	}

	v.detailBox.SetVisible(true)
}

// renderForm populates the form box with editable entries for the given item.
func (v *View) renderForm(item vault.Item) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Clear existing children and dynamic callbacks.
	for {
		child := v.formBox.GetFirstChild()
		if child == nil || child.Ptr == 0 {
			break
		}
		v.formBox.Remove(child)
	}
	v.resetDynamicCallbacks()

	editable := EditableFromItem(item)

	// Back button
	backBtn := gtklib.NewButtonWithLabel("← Back")
	backClickedCb := func(_ gtklib.Button) {
		v.mu.Lock()
		v.state.Back()
		v.mu.Unlock()
		idleAddOnce(func() { v.render() })
	}
	handler := backBtn.ConnectClicked(&backClickedCb)
	v.retainDynamic(&backBtn.Object, handler, backClickedCb)
	v.formBox.Append(&backBtn.Widget)

	// Scrollable content area
	scrollWin := gtklib.NewScrolledWindow()
	scrollWin.SetVexpand(true)
	formContent := gtklib.NewBox(gtklib.OrientationVerticalValue, 4)
	scrollWin.SetChild(&formContent.Widget)
	v.formBox.Append(&scrollWin.Widget)

	// Common: Name entry
	nameText := "Name"
	nameLabel := gtklib.NewLabel(&nameText)
	formContent.Append(&nameLabel.Widget)
	nameEntry := gtklib.NewEntry()
	nameEntry.SetText(editable.Name)
	formContent.Append(&nameEntry.Widget)

	// Declare all type-specific entry pointers.
	var usernameEntry, uriEntry, pwEntry, totpEntry *gtklib.Entry
	var chEntry, brandEntry, numEntry, expMEntry, expYEntry, codeEntry *gtklib.Entry
	var fnEntry, lnEntry, emailEntry, phoneEntry, idUserEntry *gtklib.Entry
	var ssnEntry, passportEntry, licenseEntry *gtklib.Entry

	switch item.Type {
	case vault.ItemTypeLogin:
		uText := "Username"
		usernameLabel := gtklib.NewLabel(&uText)
		formContent.Append(&usernameLabel.Widget)
		usernameEntry = gtklib.NewEntry()
		usernameEntry.SetText(editable.Username)
		formContent.Append(&usernameEntry.Widget)

		uriText := "URI"
		uriLabel := gtklib.NewLabel(&uriText)
		formContent.Append(&uriLabel.Widget)
		uriEntry = gtklib.NewEntry()
		uriEntry.SetText(editable.URI)
		formContent.Append(&uriEntry.Widget)

		pwText := "Password"
		pwLabel := gtklib.NewLabel(&pwText)
		formContent.Append(&pwLabel.Widget)
		pwEntry = gtklib.NewEntry()
		pwEntry.SetText(editable.Password)
		pwEntry.SetVisibility(false)
		formContent.Append(&pwEntry.Widget)

		totpText := "TOTP"
		totpLabel := gtklib.NewLabel(&totpText)
		formContent.Append(&totpLabel.Widget)
		totpEntry = gtklib.NewEntry()
		totpEntry.SetText(editable.TOTP)
		totpEntry.SetVisibility(false)
		formContent.Append(&totpEntry.Widget)

	case vault.ItemTypeSecureNote:
		// No additional fields beyond Name and Notes.

	case vault.ItemTypeCard:
		chText := "Cardholder name"
		chLabel := gtklib.NewLabel(&chText)
		formContent.Append(&chLabel.Widget)
		chEntry = gtklib.NewEntry()
		chEntry.SetText(editable.CardholderName)
		formContent.Append(&chEntry.Widget)

		brandText := "Brand"
		brandLabel := gtklib.NewLabel(&brandText)
		formContent.Append(&brandLabel.Widget)
		brandEntry = gtklib.NewEntry()
		brandEntry.SetText(editable.CardBrand)
		formContent.Append(&brandEntry.Widget)

		numText := "Number"
		numLabel := gtklib.NewLabel(&numText)
		formContent.Append(&numLabel.Widget)
		numEntry = gtklib.NewEntry()
		numEntry.SetText(editable.CardNumber)
		numEntry.SetVisibility(false)
		formContent.Append(&numEntry.Widget)

		expMText := "Exp month"
		expMLabel := gtklib.NewLabel(&expMText)
		formContent.Append(&expMLabel.Widget)
		expMEntry = gtklib.NewEntry()
		expMEntry.SetText(editable.CardExpMonth)
		formContent.Append(&expMEntry.Widget)

		expYText := "Exp year"
		expYLabel := gtklib.NewLabel(&expYText)
		formContent.Append(&expYLabel.Widget)
		expYEntry = gtklib.NewEntry()
		expYEntry.SetText(editable.CardExpYear)
		formContent.Append(&expYEntry.Widget)

		codeText := "Code"
		codeLabel := gtklib.NewLabel(&codeText)
		formContent.Append(&codeLabel.Widget)
		codeEntry = gtklib.NewEntry()
		codeEntry.SetText(editable.CardCode)
		codeEntry.SetVisibility(false)
		formContent.Append(&codeEntry.Widget)

	case vault.ItemTypeIdentity:
		fnText := "First name"
		fnLabel := gtklib.NewLabel(&fnText)
		formContent.Append(&fnLabel.Widget)
		fnEntry = gtklib.NewEntry()
		fnEntry.SetText(editable.IdentityFirstName)
		formContent.Append(&fnEntry.Widget)

		lnText := "Last name"
		lnLabel := gtklib.NewLabel(&lnText)
		formContent.Append(&lnLabel.Widget)
		lnEntry = gtklib.NewEntry()
		lnEntry.SetText(editable.IdentityLastName)
		formContent.Append(&lnEntry.Widget)

		emailText := "Email"
		emailLabel := gtklib.NewLabel(&emailText)
		formContent.Append(&emailLabel.Widget)
		emailEntry = gtklib.NewEntry()
		emailEntry.SetText(editable.IdentityEmail)
		formContent.Append(&emailEntry.Widget)

		phoneText := "Phone"
		phoneLabel := gtklib.NewLabel(&phoneText)
		formContent.Append(&phoneLabel.Widget)
		phoneEntry = gtklib.NewEntry()
		phoneEntry.SetText(editable.IdentityPhone)
		formContent.Append(&phoneEntry.Widget)

		idUserText := "Username"
		idUserLabel := gtklib.NewLabel(&idUserText)
		formContent.Append(&idUserLabel.Widget)
		idUserEntry = gtklib.NewEntry()
		idUserEntry.SetText(editable.IdentityUsername)
		formContent.Append(&idUserEntry.Widget)

		ssnText := "SSN"
		ssnLabel := gtklib.NewLabel(&ssnText)
		formContent.Append(&ssnLabel.Widget)
		ssnEntry = gtklib.NewEntry()
		ssnEntry.SetText(editable.IdentitySSN)
		ssnEntry.SetVisibility(false)
		formContent.Append(&ssnEntry.Widget)

		passportText := "Passport number"
		passportLabel := gtklib.NewLabel(&passportText)
		formContent.Append(&passportLabel.Widget)
		passportEntry = gtklib.NewEntry()
		passportEntry.SetText(editable.IdentityPassportNumber)
		passportEntry.SetVisibility(false)
		formContent.Append(&passportEntry.Widget)

		licenseText := "License number"
		licenseLabel := gtklib.NewLabel(&licenseText)
		formContent.Append(&licenseLabel.Widget)
		licenseEntry = gtklib.NewEntry()
		licenseEntry.SetText(editable.IdentityLicenseNumber)
		licenseEntry.SetVisibility(false)
		formContent.Append(&licenseEntry.Widget)
	}

	// Notes entry (for all types)
	notesText := "Notes"
	notesLabel := gtklib.NewLabel(&notesText)
	formContent.Append(&notesLabel.Widget)
	notesEntry := gtklib.NewEntry()
	notesEntry.SetText(editable.Notes)
	formContent.Append(&notesEntry.Widget)

	// Snapshot current item under lock for the save goroutine.
	current := v.currentItem
	isUpdate := current.ID != ""

	// Save button
	saveBtn := gtklib.NewButtonWithLabel("Save")
	saveCb := func(_ gtklib.Button) {
		e := EditableFromItem(current)
		e.Name = nameEntry.GetText()
		e.Notes = notesEntry.GetText()

		switch item.Type {
		case vault.ItemTypeLogin:
			e.Username = usernameEntry.GetText()
			e.URI = uriEntry.GetText()
			e.Password = pwEntry.GetText()
			e.TOTP = totpEntry.GetText()
		case vault.ItemTypeSecureNote:
			// Name and Notes already set.
		case vault.ItemTypeCard:
			e.CardholderName = chEntry.GetText()
			e.CardBrand = brandEntry.GetText()
			e.CardNumber = numEntry.GetText()
			e.CardExpMonth = expMEntry.GetText()
			e.CardExpYear = expYEntry.GetText()
			e.CardCode = codeEntry.GetText()
		case vault.ItemTypeIdentity:
			e.IdentityFirstName = fnEntry.GetText()
			e.IdentityLastName = lnEntry.GetText()
			e.IdentityEmail = emailEntry.GetText()
			e.IdentityPhone = phoneEntry.GetText()
			e.IdentityUsername = idUserEntry.GetText()
			e.IdentitySSN = ssnEntry.GetText()
			e.IdentityPassportNumber = passportEntry.GetText()
			e.IdentityLicenseNumber = licenseEntry.GetText()
		}

		if err := ValidateItem(e); err != nil {
			v.mu.Lock()
			v.state.Error = err.Error()
			v.mu.Unlock()
			idleAddOnce(func() { v.render() })
			return
		}

		updated := e.BuildItem()

		go func() {
			var result vault.Item
			var err error
			if isUpdate {
				result, err = v.service.Update(context.Background(), current.ID, updated)
			} else {
				result, err = v.service.Create(context.Background(), updated)
			}
			if err != nil {
				idleAddOnce(func() {
					v.mu.Lock()
					v.state.Error = err.Error()
					v.mu.Unlock()
					v.render()
				})
				return
			}
			idleAddOnce(func() {
				v.mu.Lock()
				v.state.Error = ""
				v.state.SetStatus(Status{})
				v.currentItem = result
				v.state.Mode = ModeDetail
				v.state.DetailID = result.ID
				v.mu.Unlock()
				v.renderDetail(DetailFromItem(result))
				v.render()
			})
		}()
	}
	handler1 := saveBtn.ConnectClicked(&saveCb)
	v.retainDynamic(&saveBtn.Object, handler1, saveCb)
	formContent.Append(&saveBtn.Widget)
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
