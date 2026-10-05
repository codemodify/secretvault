package svops

import (
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svrpc"
)

// What is said about items going to another vault (item.move and
// item.copy): by the managers and the CLI before and after, and by the
// daemon's own question to a program's person.

// ItemsShown is how many items a sentence names before "and N more".
const ItemsShown = 5

// CountItems says n items: "1 item", "3 items".
func CountItems(n int) string { return countOf(n, "item", "items") }

// ItemsPhrase names items in a sentence: `"a"`, `"a" and "b"`,
// `"a", "b", "c", "d", "e" and 4 more`.
func ItemsPhrase(names []string) string {
	shown := names
	if len(shown) > ItemsShown {
		shown = shown[:ItemsShown]
	}
	quoted := make([]string, 0, len(shown)+1)
	for _, n := range shown {
		quoted = append(quoted, fmt.Sprintf("%q", n))
	}
	if more := len(names) - len(shown); more > 0 {
		quoted = append(quoted, fmt.Sprintf("%d more", more))
	}
	return andList(quoted)
}

// namesOf names some of who in a sentence, those without a name as one of
// what: "alice, bob and 2 more", "a person or device without a name".
func namesOf(who []string, nameless, namelessMany string) string {
	var named []string
	none := 0
	for _, w := range who {
		if strings.TrimSpace(w) == "" {
			none++
			continue
		}
		named = append(named, fmt.Sprintf("%q", w))
	}
	if len(named) > ItemsShown {
		none += len(named) - ItemsShown
		named = named[:ItemsShown]
		return andList(append(named, fmt.Sprintf("%d more", none)))
	}
	switch {
	case none == 1:
		named = append(named, nameless)
	case none > 1:
		named = append(named, fmt.Sprintf("%d %s", none, namelessMany))
	}
	return andList(named)
}

// ReadersText says who besides the person can read what is put in vault,
// as r tells; "" when nobody can. Moving or copying items there shows
// them to every one of them.
func ReadersText(vault string, r *svrpc.VaultReaders) string {
	if !r.Anyone() {
		return ""
	}
	var who []string
	if len(r.People) > 0 {
		who = append(who, namesOf(r.People, "a person or device without a name", "people or devices without a name")+
			" open it with keys of their own")
	}
	if len(r.Trustees) > 0 {
		who = append(who, namesOf(r.Trustees, "someone", "others")+" can get it through emergency access")
	}
	if len(r.Devices) > 0 {
		who = append(who, "the devices "+namesOf(r.Devices, "one without a name", "without a name")+" have used it")
	}
	if r.Sync != "" {
		who = append(who, "it syncs through "+r.Sync+" with every device that joins it")
	}
	return fmt.Sprintf("Vault %s is not yours alone: %s. All of them will be able to read the items there.", vault, andList(who))
}

// MovePlain asks before the items of plan (a MoveParams.Plan reply) go to
// its other vault: moved (copy false) or copied.
func MovePlain(plan svrpc.MoveResult, copy bool) Plain {
	n := len(plan.Items)
	p := Plain{Details: append([]string(nil), plan.Items...)}
	if copy {
		p.Title = fmt.Sprintf("Copy %s to %s?", CountItems(n), plan.To)
		p.Summary = fmt.Sprintf("A copy of %s goes to vault %s: %s. Vault %s keeps them as they are.",
			CountItems(n), plan.To, ItemsPhrase(plan.Items), plan.Vault)
		p.Action = "Copy " + CountItems(n)
	} else {
		p.Title = fmt.Sprintf("Move %s to %s?", CountItems(n), plan.To)
		p.Summary = fmt.Sprintf("%s goes from vault %s to vault %s: %s. "+
			"Vault %s keeps them in its deleted items, from which they can be brought back.",
			SentenceStart(CountItems(n)), plan.Vault, plan.To, ItemsPhrase(plan.Items), plan.Vault)
		if n > 1 {
			p.Summary = strings.Replace(p.Summary, " goes from ", " go from ", 1)
		}
		p.Action = "Move " + CountItems(n)
	}
	p.Summary += " Their attached files go with them; their history stays behind."
	if who := ReadersText(plan.To, plan.Readers); who != "" {
		p.Notes = append(p.Notes, who)
	}
	return p
}

// MovedText says what became of the items after a move or copy, from its
// reply, or from the MoveResult in the Data of its error.
func MovedText(r svrpc.MoveResult, copy bool) string {
	verb, past := "Moved", "moved"
	if copy {
		verb, past = "Copied", "copied"
	}
	if len(r.Both) == 0 && len(r.NotDone) == 0 {
		s := fmt.Sprintf("%s %s to vault %s.", verb, CountItems(len(r.Done)), r.To)
		if !copy && len(r.Done) > 0 {
			s += fmt.Sprintf(" Vault %s's deleted items can bring them back.", r.Vault)
		}
		return s
	}
	var parts []string
	if len(r.Done) > 0 {
		parts = append(parts, fmt.Sprintf("%s %s to vault %s", past, CountItems(len(r.Done)), r.To))
	}
	if len(r.Both) > 0 {
		parts = append(parts, fmt.Sprintf("%s in both vaults (%s)", CountItems(len(r.Both)), ItemsPhrase(r.Both)))
	}
	if len(r.NotDone) > 0 {
		parts = append(parts, fmt.Sprintf("%s still in vault %s only (%s)", CountItems(len(r.NotDone)), r.Vault, ItemsPhrase(r.NotDone)))
	}
	return SentenceStart(andList(parts)) + ". Nothing was lost: try again, or delete what is in both vaults from one of them."
}
