package svmanager

import (
	"context"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Deleted items, and bringing one back; an item's reference, for the
// programs that read it (env files, templates, configuration).

// showDeleted lists the vault's deleted items (the CLI's ls --deleted),
// each of which can be restored (the CLI's restore NAME).
func (m *Manager) showDeleted() {
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	var del []svrpc.DeletedItem
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		del, err = c.Deleted(ctx, vault, "")
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			m.reloadVaults()
			return
		}
		m.reloadVaults()
		t := table("Deleted items", []widgets.TableColumn{
			{Title: "Name"}, {Title: "Kind", Width: 80}, {Title: "Deleted", Width: 140},
		}, len(del), func(r, c int) string {
			d := del[r]
			switch c {
			case 0:
				return d.Name
			case 1:
				return d.Kind
			}
			return d.Deleted.Local().Format("2006-01-02 15:04")
		})
		note := "Items deleted from vault " + vault + ". Bring one back, and it is as it was before it was deleted."
		if len(del) == 0 {
			note = "Nothing has been deleted from vault " + vault + "."
		}
		var d *dialog
		restore := widgets.NewButton(svops.RestoreDeletedAction, nil)
		restore.SetEnabled(len(del) > 0)
		restore.OnClick = func() {
			i := selected(t)
			if i < 0 {
				return
			}
			name := del[i].Name
			var e svrpc.Entry
			m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
				e, err = c.Restore(ctx, svrpc.RestoreParams{Vault: vault, Name: name})
				return err
			}, func(err error) {
				if err != nil {
					m.fail(err)
					return
				}
				d.Close()
				m.say("Brought %s back.", e.Item.Name)
				if vault == m.vault {
					m.cursor = name
					m.loadItems()
				}
			})
		}
		t.OnActivate = func(int) { restore.OnClick() }
		close := widgets.NewButton("Close", func() { d.Close() })
		body := widgets.NewColumn(m.paragraph(note), widgets.NewHeightBox(260, t)).WithGap(gap)
		d = m.showDialog("Deleted items", body, widgets.NewButtonBox().AddButton(restore, widgets.RoleAction).AddButton(close, widgets.RoleReject), t, nil)
	})
}

// copyReference copies a reference to the target item (sv://VAULT/ITEM),
// or to one of its fields (sv://VAULT/ITEM#FIELD): what an env file, a
// template or another program's configuration names it by, for the CLI's
// read, run and inject to resolve. It holds no secret.
func (m *Manager) copyReference() {
	name := m.targetName()
	if name == "" {
		m.say("Choose an item first.")
		return
	}
	vault := m.vault
	fields := []string{"its secret (the password)"}
	var names []string
	if e := m.entry(name); m.cur != nil && m.cur.Item.Name == name {
		for _, f := range m.cur.Item.Fields {
			names = append(names, f.Name)
		}
	} else if e != nil {
		for _, f := range e.Item.Fields {
			names = append(names, f.Name)
		}
	}
	for _, n := range names {
		fields = append(fields, "the field "+n)
	}
	f := m.newForm("Copy a reference to " + name)
	f.intro("A reference names a secret without holding it, for scripts and settings files to use. " +
		"Whatever reads it through secretvault asks you first, as any program's read does.")
	which := f.choice("Refer to", fields, 0)
	named := f.check("Name vault "+vault+" in it (else: the default vault)", true)
	f.show("Copy the reference", func() {
		r := svrpc.Ref{Item: name}
		if named.Checked {
			r.Vault = vault
		}
		if i := which.Selected - 1; i >= 0 && i < len(names) {
			r.Field = names[i]
		}
		f.close()
		m.copyValue([]byte(r.String()), "The reference", "")
	})
}
