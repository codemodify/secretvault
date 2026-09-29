package svd

import (
	"context"

	"github.com/codemodify/secretvault/svdbus"
)

// Secret Service prompts. A method that needs the person returns a prompt
// object instead of an answer; the program calls its Prompt method, the
// daemon asks (unlock, consent) in the background, and the answer arrives
// as the prompt's Completed signal. Dismiss, or the program leaving,
// cancels it.

type ssPrompt struct {
	owner  string // the program that may use it
	run    func(ctx context.Context) (result svdbus.Variant, dismissed bool)
	cancel context.CancelFunc
	ctx    context.Context
	used   bool
}

func (ss *secretService) newPrompt(c *ssCaller, owner string, run func(context.Context) (svdbus.Variant, bool)) svdbus.ObjectPath {
	ctx, cancel := context.WithCancel(context.Background())
	path := ss.newPath(ssPrompts)
	ss.mu.Lock()
	ss.prompts[path] = &ssPrompt{owner: owner, run: run, cancel: cancel, ctx: ctx}
	ss.mu.Unlock()
	return path
}

func (ss *secretService) promptInterface(path svdbus.ObjectPath, pr *ssPrompt) *svdbus.Interface {
	complete := func(dismissed bool, result svdbus.Variant) {
		ss.mu.Lock()
		delete(ss.prompts, path)
		ss.mu.Unlock()
		pr.cancel()
		msg := svdbus.NewSignal(path, ifPrompt, "Completed", dismissed, result)
		msg.Destination = pr.owner
		ss.bus.Send(context.Background(), msg)
	}
	return &svdbus.Interface{
		Name: ifPrompt,
		Methods: []*svdbus.Method{
			{Name: "Prompt", In: args("window-id", "s"), Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
				if call.Sender() != pr.owner {
					return nil, errDenied
				}
				ss.mu.Lock()
				if pr.used {
					ss.mu.Unlock()
					return nil, svdbus.NewError(svdbus.ErrorFailed, "the prompt was already shown")
				}
				pr.used = true
				ss.mu.Unlock()
				go func() {
					result, dismissed := pr.run(pr.ctx)
					if pr.ctx.Err() != nil {
						dismissed = true
					}
					complete(dismissed, result)
				}()
				return nil, nil
			}},
			{Name: "Dismiss", Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
				if call.Sender() != pr.owner {
					return nil, errDenied
				}
				ss.mu.Lock()
				used := pr.used
				ss.mu.Unlock()
				pr.cancel()
				if !used {
					complete(true, svdbus.MakeVariant(""))
				}
				return nil, nil
			}},
		},
		Signals: []*svdbus.Signal{{Name: "Completed", Args: args("dismissed", "b", "result", "v")}},
	}
}
