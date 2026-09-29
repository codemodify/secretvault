package svd

import "github.com/codemodify/secretvault/svrpc"

// Session events lock vaults: screen lock and sleep lock the vaults whose
// AutoLock asks for it, and the end of the user's last session locks
// every vault. The watchers are per platform (session_linux.go); they call
// these.

// ScreenLocked locks every vault set to lock with the screen.
func (d *Daemon) ScreenLocked() {
	d.lockWhere(func(a svrpc.AutoLock) bool { return a.OnScreenLock }, "screen locked")
}

// Sleeping locks every vault set to lock on sleep.
func (d *Daemon) Sleeping() {
	d.lockWhere(func(a svrpc.AutoLock) bool { return a.OnSleep }, "going to sleep")
}

// LoggedOut locks every vault: the user's last session has ended.
func (d *Daemon) LoggedOut() { d.LockAll("logged out") }

func (d *Daemon) lockWhere(when func(svrpc.AutoLock) bool, why string) {
	d.mu.Lock()
	var hit []*managedVault
	for _, mv := range d.vaults {
		if when(mv.cfg.AutoLock) {
			hit = append(hit, mv)
		}
	}
	d.mu.Unlock()
	for _, mv := range hit {
		d.lock(mv, why)
	}
}
