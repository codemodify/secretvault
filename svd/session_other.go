//go:build !linux

package svd

import "context"

// WatchSession follows screen lock, sleep and logout. Windows
// (WTSRegisterSessionNotification, power broadcasts) and macOS
// (distributed notifications) arrive with their platform work; until then
// vaults lock on idle, on request, and when the daemon stops.
func (d *Daemon) WatchSession(context.Context) {}
