//go:build linux

package svfido

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Devices lists the FIDO security keys plugged in, from sysfs. It opens
// none of them.
func Devices() ([]DeviceInfo, error) {
	return enumerate("/sys/class/hidraw", "/dev")
}

func unsupported() string { return "security keys are not supported on this system" }

// openTransport opens a hidraw node.
func openTransport(info DeviceInfo) (Transport, error) {
	fd, err := unix.Open(info.Path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return nil, &PermissionError{Path: info.Path, Name: info.Name, Err: err}
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: info.Path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		unix.Close(fd)
		return nil, fmt.Errorf("svfido: %s is not a device", info.Path)
	}
	return &hidraw{fd: fd}, nil
}

// hidraw is a Transport on a /dev/hidraw node. FIDO devices use no report
// IDs, so each write starts with a zero report ID and each read is the
// bare report.
type hidraw struct {
	fd int
}

func (h *hidraw) WriteReport(report []byte) error {
	buf := make([]byte, 1+len(report))
	copy(buf[1:], report)
	for {
		n, err := unix.Write(h.fd, buf)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			if _, err := unix.Poll([]unix.PollFd{{Fd: int32(h.fd), Events: unix.POLLOUT}}, 1000); err != nil && !errors.Is(err, unix.EINTR) {
				return err
			}
			continue
		case errors.Is(err, unix.ENODEV), errors.Is(err, unix.EIO):
			return ErrGone
		case err != nil:
			return err
		case n != len(buf):
			return fmt.Errorf("svfido: wrote %d of %d bytes of a report", n, len(buf))
		}
		return nil
	}
}

func (h *hidraw) ReadReport(report []byte, deadline time.Time) (int, error) {
	for {
		ms := int(time.Until(deadline).Milliseconds())
		if ms < 0 {
			return 0, os.ErrDeadlineExceeded
		}
		fds := []unix.PollFd{{Fd: int32(h.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, ms)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			if time.Now().Before(deadline) {
				continue
			}
			return 0, os.ErrDeadlineExceeded
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 && fds[0].Revents&unix.POLLIN == 0 {
			return 0, ErrGone
		}
		r, err := unix.Read(h.fd, report)
		switch {
		case errors.Is(err, unix.EINTR), errors.Is(err, unix.EAGAIN):
			continue
		case errors.Is(err, unix.ENODEV), errors.Is(err, unix.EIO):
			return 0, ErrGone
		case err != nil:
			return 0, err
		case r == 0:
			return 0, ErrGone
		}
		return r, nil
	}
}

func (h *hidraw) Close() error { return unix.Close(h.fd) }
