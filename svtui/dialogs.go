package svtui

import "github.com/rivo/tview"

// The dialog page holds one dialog at a time. A dialog that comes while
// another is up (the answer to an earlier request, a question from a
// worker) waits for it to close, rather than replacing it: whatever the
// first holds (a passphrase being typed, a plan with secrets behind it)
// is never dropped unwiped. Each dialog says how to cancel it, which
// runs however it goes: by its own buttons, closed from outside (the
// daemon going away, quitting), or dropped while it waits.

// pendingDialog is a dialog waiting for the one up to close.
type pendingDialog struct {
	id     int
	open   func()
	cancel func()
}

// openDialog shows a dialog on the dialog page, or queues it while
// another is up, and returns its number; cancel (if any) runs when it
// goes without being acted on.
func (u *UI) openDialog(p, focus tview.Primitive, cancel func()) int {
	u.dialogSeq++
	id := u.dialogSeq
	u.showDialog(id, p, focus, cancel)
	return id
}

func (u *UI) showDialog(id int, p, focus tview.Primitive, cancel func()) {
	if u.pages.HasPage(pageDialog) {
		u.dialogQueue = append(u.dialogQueue, pendingDialog{id: id, cancel: cancel,
			open: func() { u.showDialog(id, p, focus, cancel) }})
		return
	}
	u.dialogID, u.dialogCancel = id, cancel
	u.openPage(pageDialog, p, focus)
}

// closeDialog takes dialog id down: from the screen if it is up, from
// the queue if it waits. Its cancel runs if it has not been acted on.
func (u *UI) closeDialog(id int) {
	if u.dialogID == id && u.pages.HasPage(pageDialog) {
		u.closePage(pageDialog)
		return
	}
	for i, d := range u.dialogQueue {
		if d.id == id {
			u.dialogQueue = append(u.dialogQueue[:i], u.dialogQueue[i+1:]...)
			if d.cancel != nil {
				d.cancel()
			}
			return
		}
	}
}

// dialogClosed runs when the dialog page goes: the dialog's cancel (a
// no-op when it was acted on), then the next dialog waiting.
func (u *UI) dialogClosed() {
	cancel := u.dialogCancel
	u.dialogID, u.dialogCancel = 0, nil
	if cancel != nil {
		cancel()
	}
	if len(u.dialogQueue) > 0 {
		// After whatever closed this one has finished: it may open a
		// dialog of its own, and the next may be dropped meanwhile.
		u.post(u.openNextDialog)
	}
}

// openNextDialog opens the dialog that has waited longest, unless one is
// up (its closing calls this again).
func (u *UI) openNextDialog() {
	if u.pages.HasPage(pageDialog) || len(u.dialogQueue) == 0 {
		return
	}
	next := u.dialogQueue[0]
	u.dialogQueue = u.dialogQueue[1:]
	next.open()
}

// dropDialogs cancels every dialog waiting (the daemon went away, or the
// program is quitting).
func (u *UI) dropDialogs() {
	q := u.dialogQueue
	u.dialogQueue = nil
	for _, d := range q {
		if d.cancel != nil {
			d.cancel()
		}
	}
}
