package svtui

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Items going to another vault (item.move, item.copy): the item, or
// every item of the vault. The vault is chosen, the daemon says what would go and who else
// reads that vault (a plan), and only the person's yes to it moves them:
// for secretvault's own programs, that is the consent.

// moveItem moves the item an action is about to another vault, or copies
// it there.
func (u *UI) moveItem(copy bool) {
	name := u.targetName()
	if name == "" {
		u.say("Choose an item first.")
		return
	}
	verb := moveVerb(copy)
	u.moveTo(copy, svrpc.MoveParams{Vault: u.vault, Names: []string{name}},
		fmt.Sprintf("%s %s to which vault?", verb, name), "it")
}

// moveAll moves, or copies, every item of the vault shown to another.
func (u *UI) moveAll(copy bool) {
	if !u.needVault() {
		return
	}
	vault := u.vault
	u.moveTo(copy, svrpc.MoveParams{Vault: vault, Prefix: svrpc.PrefixOf("")},
		fmt.Sprintf("%s every item of %s to which vault?", moveVerb(copy), vault), "them")
}

func moveVerb(copy bool) string {
	if copy {
		return "Copy"
	}
	return "Move"
}

// moveTo asks which other vault the items of p go to (question), then
// what the daemon says would go, and moves or copies them on a yes. it
// is how the items are spoken of: "it", "them".
func (u *UI) moveTo(copy bool, p svrpc.MoveParams, question, it string) {
	var others []string
	for _, v := range u.vaults {
		if v.Name != p.Vault && v.ID != "" {
			others = append(others, v.Name)
		}
	}
	if len(others) == 0 {
		u.say("There is no other vault to %s %s to: N makes one.", strings.ToLower(moveVerb(copy)), it)
		return
	}
	u.choose(question, others, func(i int) {
		p.To = others[i]
		u.planMove(copy, p)
	})
}

// moving is MoveItems or CopyItems.
func moving(copy bool) func(*secretvault.Client, context.Context, svrpc.MoveParams) (svrpc.MoveResult, error) {
	if copy {
		return (*secretvault.Client).CopyItems
	}
	return (*secretvault.Client).MoveItems
}

// planMove shows what moving (or copying) p's items would do, and does it
// on a yes.
func (u *UI) planMove(copy bool, p svrpc.MoveParams) {
	call := moving(copy)
	plan := p
	plan.Plan = true
	var res svrpc.MoveResult
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		res, err = call(c, ctx, plan)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			u.reloadVaults() // the plan may have unlocked a vault
			return
		}
		u.reloadVaults()
		// What goes is what was shown: the items the plan named, not
		// whatever the vault holds by the time the person says yes.
		do := svrpc.MoveParams{Vault: p.Vault, To: p.To, Names: slices.Clone(res.Items)}
		u.showPlan(svops.MovePlain(res, copy), func() { u.doMove(copy, do) })
	})
}

// doMove moves (or copies) p's items, and says what became of them.
func (u *UI) doMove(copy bool, p svrpc.MoveParams) {
	call := moving(copy)
	var res svrpc.MoveResult
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		res, err = call(c, ctx, p)
		return err
	}, func(err error) {
		if err != nil && len(res.Done)+len(res.Both)+len(res.NotDone) == 0 {
			u.fail(err)
			return
		}
		if !copy && u.cur != nil && p.Vault == u.vault && slices.Contains(res.Done, u.cur.Item.Name) {
			u.closeItem()
		}
		u.say("%s", svops.MovedText(res, copy))
		if p.Vault == u.vault {
			u.loadItems()
		} else {
			u.reloadVaults()
		}
	})
}
