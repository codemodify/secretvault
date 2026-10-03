package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svclip"
	"github.com/codemodify/secretvault/svcrypto"
)

// Copying to the clipboard. The clipboard is served by whoever set it, so
// the copy is made by a copy of this program running on its own
// (secretvault __clip SECONDS, secret on stdin): it takes the clipboard,
// says so on stdout, serves pastes, and clears the clipboard when time is
// up. The command that asked returns as soon as the copy is in place.

// clipCommand is the hidden helper's name.
const clipCommand = "__clip"

// copySecret puts secret on the clipboard for ttl, via the helper.
func (c *cli) copySecret(secret []byte, ttl time.Duration) (string, error) {
	if c.clip != nil {
		return c.clip(secret, ttl)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(exe, clipCommand, strconv.Itoa(int(ttl.Seconds())))
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
		return "", err
	}
	in.Write(secret)
	in.Close()
	status := make(chan string, 1)
	go func() {
		// Read before waiting: Wait closes the pipe, and would lose the
		// error line of a helper that fails at once.
		line, _ := bufio.NewReader(out).ReadString('\n')
		status <- strings.TrimSpace(line)
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

// clipHelper is the hidden `secretvault __clip SECONDS` command.
func clipHelper(args []string) int {
	_ = svcrypto.NoCoreDumps()
	secs := 30
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 && n <= 3600 {
			secs = n
		}
	}
	// One buffer, never grown: io.ReadAll would leave each buffer it
	// outgrew behind, unwiped, with a part of the secret in it.
	buf := make([]byte, 1<<20)
	defer clear(buf)
	n, err := io.ReadFull(os.Stdin, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		err = nil
	}
	secret := buf[:n]
	if err != nil || len(secret) == 0 {
		fmt.Println("error: nothing to copy")
		return 1
	}
	_, err = svclip.Copy(secret, time.Duration(secs)*time.Second, func(backend string) {
		fmt.Println("ok " + backend)
		os.Stdout.Close() // the asker has what it needs; nothing more is written
	})
	if err != nil {
		fmt.Println("error: " + err.Error())
		return 1
	}
	return 0
}
