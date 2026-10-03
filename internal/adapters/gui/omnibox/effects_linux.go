//go:build linux && !nogtk

package omnibox

import "time"

// run applies fn to the controller under the view lock and then performs the
// effects it returns. It must be called on the GTK main thread: effects touch
// widgets directly. Work that completes off-thread re-enters through
// idleAddOnce.
func (v *View) run(fn func(c *Controller) []Effect) {
	v.mu.Lock()
	effects := fn(v.ctrl)
	v.mu.Unlock()
	v.perform(effects)
}

// runIdle is run deferred to the next main-loop iteration.
func (v *View) runIdle(fn func(c *Controller) []Effect) {
	idleAddOnce(func() { v.run(fn) })
}

func (v *View) reportError(operation string, err error) {
	logOverlayError(v.ctx, operation, err)
}

// perform executes effects in order on the GTK main thread. It is the only
// place where controller decisions turn into widget updates, timers, service
// calls, and goroutines.
func (v *View) perform(effects []Effect) {
	for _, effect := range effects {
		switch e := effect.(type) {
		case EffectRender:
			v.render()
		case EffectRenderTabs:
			v.updateTabStyles()
		case EffectRenderRows:
			v.renderRows()
		case EffectRenderStatus:
			v.renderStatus()
		case EffectRenderDetail:
			v.renderDetail(e.Detail)
		case EffectShowError:
			v.showError(e.Text)
		case EffectFocusSearch:
			v.searchEntry.GrabFocus()
		case EffectSetSyncSuspended:
			v.setBackgroundSyncSuspended(e.Suspended)
		case EffectClose:
			v.performClose(e.Delay)
		case EffectScheduleSearch:
			v.scheduleSearch(e)
		case EffectScheduleRowsRefresh:
			v.scheduleRowsRefresh(e)
		case EffectCancelRowsRefresh:
			v.cancelRowsRefresh()
		case EffectFetchRows:
			go func() {
				res := FetchRows(v.ctx, v.service, e.Request, v.reportError)
				v.runIdle(func(c *Controller) []Effect { return c.ApplyRows(res) })
			}()
		case EffectCopyRow:
			go func() {
				res := FetchCopy(v.ctx, v.service, v.clipboard, e.Request, v.reportError)
				v.runIdle(func(c *Controller) []Effect { return c.ApplyCopy(res) })
			}()
		case EffectLoadDetail:
			go func() {
				res := FetchDetail(v.ctx, v.service, e.Row, v.reportError)
				v.runIdle(func(c *Controller) []Effect { return c.ApplyDetail(res) })
			}()
		case EffectMutateItem:
			go func() {
				res := RunMutation(v.ctx, v.service, e.Request, v.reportError)
				v.runIdle(func(c *Controller) []Effect { return c.ApplyMutation(res) })
			}()
		case EffectResolveConflict:
			go func() {
				res := ResolveAndSync(v.ctx, v.service, e.Request, v.reportError)
				idleAddOnce(func() {
					query := v.searchEntry.GetText()
					v.run(func(c *Controller) []Effect { return c.ApplyResolve(res, query) })
				})
			}()
		case EffectShowForm:
			v.showForm(e.Session)
		case EffectFormError:
			v.setFormError(e.Session, e.Text)
		case EffectFormSaving:
			v.setFormSaving(e.Session, e.Saving)
		case EffectSaveForm:
			go func() {
				res := SaveForm(v.ctx, v.service, e.Request, v.reportError)
				idleAddOnce(func() {
					query := v.searchEntry.GetText()
					v.run(func(c *Controller) []Effect { return c.ApplySave(res, query) })
				})
			}()
		}
	}
}

func (v *View) performClose(delay time.Duration) {
	if delay <= 0 {
		idleAddOnce(v.quit)
		return
	}
	time.AfterFunc(delay, func() { idleAddOnce(v.quit) })
}

// scheduleSearch (re)starts the debounce timer. The timer fires on its own
// goroutine, so it hops to the main loop before touching the controller.
func (v *View) scheduleSearch(e EffectScheduleSearch) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.searchTimer != nil {
		v.searchTimer.Stop()
	}
	v.searchTimer = time.AfterFunc(e.Delay, func() {
		v.runIdle(func(c *Controller) []Effect { return c.Search(e.Query) })
	})
}

func (v *View) scheduleRowsRefresh(e EffectScheduleRowsRefresh) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.syncStatusTimer != nil {
		v.syncStatusTimer.Stop()
	}
	v.syncStatusTimer = time.AfterFunc(e.Delay, func() {
		if v.ctx.Err() != nil {
			return
		}
		idleAddOnce(func() {
			if v.ctx.Err() != nil {
				return
			}
			query := v.searchEntry.GetText()
			v.run(func(c *Controller) []Effect { return c.RefreshTimerFired(e.Token, query) })
		})
	})
}

func (v *View) cancelRowsRefresh() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.syncStatusTimer != nil {
		v.syncStatusTimer.Stop()
		v.syncStatusTimer = nil
	}
}
