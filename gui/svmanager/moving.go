package svmanager

import (
	"context"
	"fmt"
	"slices"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Items going to another vault: Move to vault… and Copy to vault… for the
// item chosen, and for the items picked together in the list; Move every
// item to vault… and Copy every item to vault… on the vault's Settings. The daemon carries them
// (item.move, item.copy), so nothing secret passes through this program.
// It is asked first what would go (a plan, which changes nothing), that
// is shown in svops's words, the same as the TUI's and the CLI's, and
// only when the person says yes is it done: that is their consent, and
// the daemon asks none of its own of secretvault's programs, only a
// vault's passphrase in this window if it needs one.

// moveItem moves the target item to another vault; copy keeps it where
// it is too.
func (m *Manager) moveItem(copy bool) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	name := m.targetName()
	if name == "" {
		m.say("Choose an item first.")
		return
	}
	m.moveTo(svrpc.MoveParams{Vault: m.vault, Names: []string{name}}, name, "it", copy)
}

// moveAll moves every item of vault to another vault; copy keeps them
// where they are too.
func (m *Manager) moveAll(vault string, copy bool) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	m.moveTo(svrpc.MoveParams{Vault: vault, Prefix: svrpc.PrefixOf("")}, "every item of "+vault, "them", copy)
}

// otherVaults are the vaults items of the one shown can go to: the
// others whose folder is there.
func (m *Manager) otherVaults() []string {
	var out []string
	for _, v := range m.vaults {
		if v.Name != m.vault && v.ID != "" {
			out = append(out, v.Name)
		}
	}
	return out
}

// moveTo asks which vault what p names goes to, then what would go
// (svops.MovePlain), and only then moves or copies it. what names it in
// the title ("github.com", "3 items"), and it is "it" or "them"
// in a sentence.
func (m *Manager) moveTo(p svrpc.MoveParams, what, it string, copy bool) {
	if m.gone {
		m.fail(errGone)
		return
	}
	title, verb, done := "Move", "move", "moves"
	if copy {
		title, verb, done = "Copy", "copy", "is copied"
	}
	others := m.otherVaults()
	if len(others) == 0 {
		m.say("There is no other vault to %s %s to: Vault › New vault… makes one.", verb, it)
		return
	}
	f := m.newForm(fmt.Sprintf("%s %s to another vault", title, what))
	which := f.choice("To vault", others, 0)
	f.note(fmt.Sprintf("Nothing %s until you have seen what would go.", done))
	f.show("Next", func() {
		q := p
		q.To = others[max(0, min(which.Selected, len(others)-1))]
		q.Plan = true
		var plan svrpc.MoveResult
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			plan, err = moveCall(ctx, c, q, copy)
			return err
		}, func() { m.confirmMove(q, plan, copy) })
	})
}

// moveCall is item.move, or item.copy.
func moveCall(ctx context.Context, c *secretvault.Client, p svrpc.MoveParams, copy bool) (svrpc.MoveResult, error) {
	if copy {
		return c.CopyItems(ctx, p)
	}
	return c.MoveItems(ctx, p)
}

// confirmMove shows the plan, and carries it out when the person says
// yes: the items it named, and only those, whatever was added to the
// vault meanwhile.
func (m *Manager) confirmMove(p svrpc.MoveParams, plan svrpc.MoveResult, copy bool) {
	if len(plan.Items) == 0 {
		m.say("There are no items there.")
		return
	}
	m.showPlan(svops.MovePlain(plan, copy), func() {
		do := svrpc.MoveParams{Vault: p.Vault, To: p.To, Names: slices.Clone(plan.Items)}
		var res svrpc.MoveResult
		m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			res, err = moveCall(ctx, c, do, copy)
			return err
		}, func(err error) { m.moved(do, res, err, copy) })
	}, nil)
}

// moved says how a move or copy went, and has the window follow it: an
// item that went is closed, and the list is listed again. An error that
// has items done, in both vaults or not done says so, and that nothing
// was lost (svops.MovedText); any other is said as it is.
func (m *Manager) moved(p svrpc.MoveParams, res svrpc.MoveResult, err error, copy bool) {
	if err != nil && len(res.Done)+len(res.Both)+len(res.NotDone) == 0 {
		m.fail(err)
		return
	}
	if res.Vault == "" {
		res.Vault = p.Vault
	}
	if res.To == "" {
		res.To = p.To
	}
	if !copy && p.Vault == m.vault {
		for _, n := range res.Done {
			if m.cursor == n {
				m.cursor = ""
			}
			if m.hist != nil && m.hist.name == n {
				m.leaveHistory()
			}
			if m.cur != nil && m.cur.Item.Name == n {
				m.closeItem()
			}
		}
	}
	m.say("%s", svops.MovedText(res, copy))
	if p.Vault == m.vault {
		m.loadItems()
	}
}
