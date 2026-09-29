//go:build !linux

package svd

func pidfdAlive(int) bool { return true }

func closeFD(int) {}
