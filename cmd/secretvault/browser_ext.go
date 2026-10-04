package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// secretvault's own browser extension (browser/extension, svext): its
// native-messaging host, and `secretvault browser extension`, which
// writes the extension out to load.

// maxWaiting is how many of the extension's requests may wait at once
// (for a person deciding, say); one more is refused as busy.
const maxWaiting = 8

// extensionHost is the host for secretvault's extension: it checks each
// request (svext.ParseRequest), answers generate itself with the
// managers' generator, and passes the rest to the daemon, the answers
// back. It holds nothing between requests, and logs nothing of them.
func (c *cli) extensionHost(origin string) error {
	var wmu sync.Mutex
	write := func(frame []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		svext.WriteFrame(c.stdout, frame)
	}
	// answer writes an answer to request id, and wipes it: one the browser
	// would not take (over its 1 MiB) is a refusal instead, not silence.
	answer := func(id string, frame []byte) {
		defer clear(frame)
		if len(frame) > svext.MaxFrame {
			frame = svext.Refusal(id, svext.Errorf(svext.CodeFailed, "the answer is too large to send"))
		}
		write(frame)
	}
	cl, err := c.connect(secretvault.Options{
		Name: "secretvault-browser",
		OnNotify: func(method string, params json.RawMessage) {
			var f svrpc.BrowserFrame
			if method == svrpc.EBrowserFrame && json.Unmarshal(params, &f) == nil && len(f.Frame) > 0 {
				write(f.Frame)
			}
		},
	})
	if err != nil {
		write(svext.DownEvent(describe(err)))
		return err
	}
	c.client = cl
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opened svrpc.BrowserOpenResult
	if err := cl.Call(ctx, svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Origin: origin, Protocol: svext.Protocol}, &opened); err != nil {
		write(svext.DownEvent(describe(err)))
		return err
	}
	waiting := make(chan struct{}, maxWaiting)
	read := make(chan error, 1)
	go func() {
		for {
			frame, err := svext.ReadFrame(c.stdin)
			if err != nil {
				read <- err
				return
			}
			r, err := svext.ParseRequest(frame)
			if err != nil {
				clear(frame)
				id := ""
				if r != nil {
					id = r.ID
				}
				write(svext.Refusal(id, err))
				continue
			}
			select {
			case waiting <- struct{}{}:
			default:
				r.Wipe()
				clear(frame)
				write(svext.Refusal(r.ID, svext.Errorf(svext.CodeBusy, "%d requests wait already", maxWaiting)))
				continue
			}
			go func() {
				defer func() { <-waiting }()
				id := r.ID
				answer(id, c.extensionAnswer(ctx, cl, r, frame))
			}()
		}
	}()
	select {
	case err := <-read:
		if errors.Is(err, io.EOF) {
			return nil // the browser closed the connection
		}
		return fmt.Errorf("reading from the browser: %w", err)
	case <-cl.Done():
		write(svext.DownEvent("secretvaultd went away"))
		return errors.New("secretvaultd went away")
	}
}

// extensionAnswer answers one checked request, wiping what it held.
func (c *cli) extensionAnswer(ctx context.Context, cl *secretvault.Client, r *svext.Request, frame []byte) []byte {
	defer clear(frame)
	defer r.Wipe()
	if r.Op == svext.OpGenerate {
		return svext.GenerateReply(r, svops.GeneratePassword)
	}
	var reply svrpc.BrowserFrame
	if err := cl.Call(ctx, svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: frame}, &reply); err != nil {
		return svext.Refusal(r.ID, svext.Errorf(svext.CodeNotRunning, "%s", describe(err)))
	}
	return reply.Frame
}

// browserExtension is `secretvault browser extension`: the extension
// written out for a family of browsers (--target): for Firefox, a zip to
// load (or a folder); for Chromium's family, a folder for Load unpacked,
// or a zip for the Chrome Web Store. With no --target, a folder is for
// Chromium and a zip for Firefox, as before there were targets.
func (c *cli) browserExtension(args []string) error {
	fs := c.flags("browser extension")
	target := fs.String("target", "", "the browsers it is for: `firefox` or chromium (Chrome, Chromium, Brave, Edge, Vivaldi)")
	out := fs.String("out", "", "write the zip to `FILE` (default: "+svops.ExtensionFileName(svops.TargetFirefox)+" here, or "+
		svops.ExtensionFileName(svops.TargetChromium)+" for chromium)")
	dir := fs.String("dir", "", "write the files into `DIR` instead (for Chromium's Load unpacked)")
	force := fs.Bool("force", false, "replace a file already there")
	if _, err := parse(fs, args, 0, 0, "[--target firefox|chromium] [--out FILE | --dir DIR] [--force]"); err != nil {
		return err
	}
	t := svops.TargetFirefox
	if *dir != "" {
		t = svops.TargetChromium
	}
	if *target != "" {
		var err error
		if t, err = svops.ParseExtensionTarget(*target); err != nil {
			return err
		}
	}
	var err error
	var lines []string
	switch {
	case *out != "" && *dir != "":
		return errors.New("--out or --dir, not both")
	case *dir != "":
		err = svops.WriteExtensionDir(*dir, t)
		lines = svops.ExtensionWrittenLines(*dir, t, true)
	default:
		file := *out
		if file == "" {
			file = svops.ExtensionFileName(t)
		}
		err = svops.WriteExtension(file, t, *force)
		if errors.Is(err, svops.ErrExtensionExists) {
			return fmt.Errorf("%w; --force replaces it", err)
		}
		lines = svops.ExtensionWrittenLines(file, t, false)
	}
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Fprintln(c.stdout, l)
	}
	return nil
}
