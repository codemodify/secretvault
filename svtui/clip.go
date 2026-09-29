package svtui

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Copying to the clipboard. Whoever sets the clipboard has to serve it
// until it is cleared, so the copy is made by the secretvault CLI
// installed beside this program, run on its own (secretvault __clip
// SECONDS, the secret on stdin): it takes the clipboard, says so on its
// first line of output ("ok BACKEND" or "error: ..."), serves pastes,
// and clears the clipboard when time is up. This program carries on as
// soon as the copy is in place.

// helperClip copies secret for ttl through the CLI beside this program.
func helperClip(secret []byte, ttl time.Duration) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	name := "secretvault"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return clipWith(filepath.Join(filepath.Dir(exe), name), secret, ttl)
}

// clipWith runs helper __clip SECONDS with secret on its stdin, and waits
// for it to say it has the clipboard.
func clipWith(helper string, secret []byte, ttl time.Duration) (string, error) {
	cmd := exec.Command(helper, "__clip", strconv.Itoa(int(ttl.Seconds())))
	in, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	detach(cmd)
	if err := cmd.Start(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("the secretvault command is not installed beside secretvault-tui")
		}
		return "", err
	}
	in.Write(secret)
	in.Close()
	status := make(chan string, 1)
	go func() {
		// Wait closes the pipe, so it comes after the reading: a helper
		// that fails at once would otherwise lose its "error: ..." line.
		// The helper closes its stdout once the copy is in place, and is
		// reaped when it has cleared the clipboard.
		line, _ := bufio.NewReader(out).ReadString('\n')
		status <- strings.TrimSpace(line)
		io.Copy(io.Discard, out)
		cmd.Wait()
	}()
	select {
	case s := <-status:
		if backend, ok := strings.CutPrefix(s, "ok "); ok {
			return backend, nil
		}
		if s == "" {
			s = "the clipboard helper stopped"
		}
		return "", errors.New(strings.TrimPrefix(s, "error: "))
	case <-time.After(10 * time.Second):
		return "", errors.New("the clipboard did not answer")
	}
}
