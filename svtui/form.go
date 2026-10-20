package svtui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The item editor, and the password generator.

// editor is the form that makes or changes an item. Secret values are
// typed into secretInputs, which keep them out of Go strings.
type editor struct {
	u     *UI
	vault string
	orig  string // the name of the item being changed; "" for a new one

	form    *tview.Form
	kind    *tview.DropDown
	kinds   []string // what ed.kind offers, as stored; it shows their names
	name    *tview.InputField
	label   *tview.InputField
	tags    *tview.InputField
	attrs   *tview.TextArea
	fixed   int // form items before the fields
	fields  []*fieldEditor
	reveal  bool
	touched bool // a field was typed into: a new item keeps its fields when the kind changes
	saving  bool

	lastSecret *secretInput // the secret field last focused, for the generator
}

// fieldEditor is one field in the editor.
type fieldEditor struct {
	name, typ string
	input     *tview.InputField // text, url, email
	area      *tview.TextArea   // json, notes, and text of several lines
	secret    *secretInput      // concealed, key, otp
	binary    []byte            // binary values are kept as they are
	item      tview.FormItem
}

func (fe *fieldEditor) value() []byte {
	switch {
	case fe.secret != nil:
		return fe.secret.value()
	case fe.area != nil:
		return []byte(fe.area.GetText())
	case fe.input != nil:
		return []byte(fe.input.GetText())
	}
	return append([]byte(nil), fe.binary...)
}

func (fe *fieldEditor) wipe() {
	if fe.secret != nil {
		fe.secret.wipe()
	}
	clear(fe.binary)
}

// fieldTypes are the types a new field may have.
var fieldTypes = []string{svcore.FieldText, svcore.FieldConcealed, svcore.FieldURL, svcore.FieldEmail,
	svcore.FieldOTP, svcore.FieldJSON, svcore.FieldKey}

// templates are the fields a new item of each kind starts with.
var templates = map[string][][2]string{
	"login":    {{"username", svcore.FieldText}, {"password", svcore.FieldConcealed}, {"url", svcore.FieldURL}},
	"password": {{"password", svcore.FieldConcealed}},
	"note":     {{"note", svcore.FieldText}},
	"card":     {{"cardholder", svcore.FieldText}, {"number", svcore.FieldConcealed}, {"expiry", svcore.FieldText}, {"cvv", svcore.FieldConcealed}},
	"identity": {{"name", svcore.FieldText}, {"email", svcore.FieldEmail}, {"phone", svcore.FieldText}, {"address", svcore.FieldText}},
	"ssh-key":  {{"private-key", svcore.FieldKey}, {"public-key", svcore.FieldText}},
	"api-key":  {{"secret", svcore.FieldConcealed}},
	"key":      {{"secret", svcore.FieldKey}},
	"kv":       {{"data", svcore.FieldJSON}},
	"otp":      {{"otp", svcore.FieldOTP}},
	"generic":  {{"secret", svcore.FieldConcealed}},
}

// newItem opens the editor on a new login, with generated (if any) as
// its password.
func (u *UI) newItem(generated []byte) {
	if u.vault == "" {
		u.say("There is no vault to put an item in.")
		return
	}
	if svops.KindRows[u.kind].Kind == "container" && generated == nil {
		// A disk's key is made with its disk.
		u.newContainer(u.vault, nil)
		return
	}
	ed := u.openEditor(nil)
	if generated != nil {
		ed.useGenerated(generated)
	}
}

// editItem opens the editor on the target item.
func (u *UI) editItem() {
	u.withItem(func(e *svrpc.Entry) {
		if svops.IsPasskey(&e.Item) {
			u.say("%s", svops.PasskeyEditNote)
			return
		}
		u.openEditor(e)
	})
}

// openEditor shows the editor, on a copy of e (nil for a new item).
func (u *UI) openEditor(e *svrpc.Entry) *editor {
	if u.editor != nil {
		u.editor.close()
	}
	ed := &editor{u: u, vault: u.vault}
	u.editor = ed
	// A new item is of the kind listed.
	it := svrpc.Item{Kind: svops.KindRows[u.kind].Kind}
	if it.Kind == "container" {
		it.Kind = "login"
	}
	if e != nil {
		it, ed.orig = e.Item, e.Item.Name
	}
	ed.form = tview.NewForm().SetItemPadding(0)
	ed.form.SetBorder(true)
	if e == nil {
		ed.form.SetTitle(" New item in " + tview.Escape(u.vault) + " — Ctrl+S saves · Esc cancels ")
	} else {
		ed.form.SetTitle(" Edit " + tview.Escape(e.Item.Name) + " — Ctrl+S saves · Esc cancels ")
	}

	ed.kinds = slices.Clone(svcore.Kinds)
	if !slices.Contains(ed.kinds, it.Kind) {
		ed.kinds = append(ed.kinds, it.Kind)
	}
	names := make([]string, len(ed.kinds))
	for i, k := range ed.kinds {
		names[i] = svops.KindText(k)
	}
	ed.kind = tview.NewDropDown().SetLabel("Kind").SetOptions(names, nil)
	ed.kind.SetCurrentOption(slices.Index(ed.kinds, it.Kind))
	ed.kind.SetSelectedFunc(func(_ string, i int) { ed.kindChanged(ed.kinds[i]) })
	ed.name = tview.NewInputField().SetLabel("Name").SetText(it.Name).SetPlaceholder("like github.com")
	ed.label = tview.NewInputField().SetLabel("Label").SetText(it.Label).SetPlaceholder("a title for people (optional)")
	ed.tags = tview.NewInputField().SetLabel("Tags").SetText(strings.Join(it.Tags, ", ")).SetPlaceholder("comma-separated (optional)")
	var attrs []string
	for _, k := range sortedKeys(it.Attrs) {
		attrs = append(attrs, k+"="+it.Attrs[k])
	}
	ed.attrs = tview.NewTextArea().SetLabel("Attributes").SetPlaceholder("key=value, one per line (optional)").SetSize(3, 0)
	ed.attrs.SetText(strings.Join(attrs, "\n"), false)
	ed.form.AddFormItem(ed.kind).AddFormItem(ed.name).AddFormItem(ed.label).AddFormItem(ed.tags).AddFormItem(ed.attrs)
	ed.fixed = ed.form.GetFormItemCount()

	if e == nil {
		ed.setTemplate(it.Kind)
	} else {
		for _, f := range it.Fields {
			ed.addField(f.Name, f.Type, f.Value)
		}
	}
	ed.form.AddButton("Save", ed.save).
		AddButton("Add field", ed.askField).
		AddButton("Remove field", ed.askRemove).
		AddButton("Generate", func() { u.showGenerator(ed.useGenerated) }).
		AddButton("Show secrets", ed.toggleReveal).
		AddButton("Cancel", ed.close)
	ed.form.SetCancelFunc(ed.close)
	ed.form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyCtrlS:
			ed.save()
		case tcell.KeyCtrlR:
			ed.toggleReveal()
		case tcell.KeyCtrlG:
			u.showGenerator(ed.useGenerated)
		default:
			return ev
		}
		return nil
	})
	ed.form.SetFocus(1)
	u.openPage(pageForm, inset(ed.form), ed.form)
	return ed
}

// inset leaves a margin round p.
func inset(p tview.Primitive) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 2, 0, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 1, 0, false).
			AddItem(p, 0, 1, true).
			AddItem(nil, 1, 0, false), 0, 1, true).
		AddItem(nil, 2, 0, false)
}

// addField adds a field to the form, holding a copy of value.
func (ed *editor) addField(name, typ string, value []byte) *fieldEditor {
	fe := &fieldEditor{name: name, typ: typ}
	label := tview.Escape(name) + " (" + typ + ")"
	switch {
	case secretType(typ):
		s := newSecretInput(label)
		s.set(value)
		s.reveal = ed.reveal
		s.changed = func() { ed.touched = true }
		s.SetFocusFunc(func() { ed.lastSecret = s })
		fe.secret, fe.item = s, s
	case typ == svcore.FieldBinary:
		tv := tview.NewTextView().SetLabel(label).SetText(fmt.Sprintf("%d bytes, kept as they are", len(value))).
			SetScrollable(false).SetSize(1, 0)
		fe.binary, fe.item = append([]byte(nil), value...), tv
	case typ == svcore.FieldJSON || bytes.ContainsRune(value, '\n') || name == "note" || name == "notes":
		a := tview.NewTextArea().SetLabel(label).SetSize(4, 0)
		a.SetText(string(value), false)
		a.SetChangedFunc(func() { ed.touched = true })
		fe.area, fe.item = a, a
	default:
		in := tview.NewInputField().SetLabel(label).SetText(string(value))
		in.SetChangedFunc(func(string) { ed.touched = true })
		fe.input, fe.item = in, in
	}
	ed.fields = append(ed.fields, fe)
	ed.form.AddFormItem(fe.item)
	return fe
}

// removeField takes field i out of the form, wiping it.
func (ed *editor) removeField(i int) {
	fe := ed.fields[i]
	fe.wipe()
	if ed.lastSecret == fe.secret {
		ed.lastSecret = nil
	}
	ed.form.RemoveFormItem(ed.fixed + i)
	ed.fields = slices.Delete(ed.fields, i, i+1)
}

// setTemplate replaces the fields with the ones a new item of kind starts
// with.
func (ed *editor) setTemplate(kind string) {
	for i := len(ed.fields) - 1; i >= 0; i-- {
		ed.removeField(i)
	}
	t, ok := templates[kind]
	if !ok {
		t = templates["generic"]
	}
	for _, f := range t {
		ed.addField(f[0], f[1], nil)
	}
	ed.touched = false
}

// kindChanged gives a new, untouched item the fields of its new kind.
func (ed *editor) kindChanged(kind string) {
	if ed.orig == "" && !ed.touched && ed.fields != nil {
		ed.setTemplate(kind)
	}
}

func (ed *editor) toggleReveal() {
	ed.reveal = !ed.reveal
	for _, fe := range ed.fields {
		if fe.secret != nil {
			fe.secret.reveal = ed.reveal
		}
	}
	label := "Show secrets"
	if ed.reveal {
		label = "Hide secrets"
	}
	if i := ed.form.GetButtonIndex("Show secrets"); i >= 0 {
		ed.form.GetButton(i).SetLabel(label)
	} else if i := ed.form.GetButtonIndex("Hide secrets"); i >= 0 {
		ed.form.GetButton(i).SetLabel(label)
	}
}

// useGenerated puts a generated password in the secret field last
// focused, else the item's password field, else a new one.
func (ed *editor) useGenerated(pw []byte) {
	target := ed.lastSecret
	if target == nil {
		for _, n := range []string{"password", "secret"} {
			for _, fe := range ed.fields {
				if fe.name == n && fe.secret != nil && target == nil {
					target = fe.secret
				}
			}
		}
	}
	if target == nil {
		for _, fe := range ed.fields {
			if fe.typ == svcore.FieldConcealed && target == nil {
				target = fe.secret
			}
		}
	}
	if target == nil {
		target = ed.addField("password", svcore.FieldConcealed, nil).secret
	}
	target.set(pw)
	ed.touched = true
}

// askField asks for a new field's name and type.
func (ed *editor) askField() {
	u := ed.u
	form := tview.NewForm()
	name := tview.NewInputField().SetLabel("Name").SetFieldWidth(30)
	typ := tview.NewDropDown().SetLabel("Type").SetOptions(fieldTypes, nil).SetCurrentOption(0)
	form.AddFormItem(name).AddFormItem(typ)
	add := func() {
		n := strings.TrimSpace(name.GetText())
		if n == "" {
			return
		}
		for _, fe := range ed.fields {
			if fe.name == n {
				u.say("The item already has a field called %s.", n)
				return
			}
		}
		_, t := typ.GetCurrentOption()
		u.closePage(pageDialog)
		ed.addField(n, t, nil)
		ed.form.SetFocus(ed.fixed + len(ed.fields) - 1)
		u.app.SetFocus(ed.form)
	}
	form.AddButton("Add", add).AddButton("Cancel", func() { u.closePage(pageDialog) })
	form.SetCancelFunc(func() { u.closePage(pageDialog) })
	form.SetBorder(true).SetTitle(" Add a field ")
	u.openDialog(centred(form, 52, 9), form, nil)
}

// askRemove asks which field to remove.
func (ed *editor) askRemove() {
	u := ed.u
	if len(ed.fields) == 0 {
		u.say("There are no fields to remove.")
		return
	}
	list := tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true)
	for i, fe := range ed.fields {
		list.AddItem(tview.Escape(fe.name)+" ("+fe.typ+")", "", 0, func() {
			u.closePage(pageDialog)
			ed.removeField(i)
			u.app.SetFocus(ed.form)
		})
	}
	list.SetDoneFunc(func() { u.closePage(pageDialog) })
	list.SetBorder(true).SetTitle(" Remove which field? — Esc keeps them all ")
	u.openDialog(centred(list, 52, len(ed.fields)+2), list, nil)
}

// item reads the form. The caller wipes the fields' values.
func (ed *editor) item() (svrpc.Item, error) {
	var it svrpc.Item
	i, _ := ed.kind.GetCurrentOption()
	it.Kind = ed.kinds[max(0, i)]
	it.Name = strings.TrimSpace(ed.name.GetText())
	if err := svcore.CheckName(it.Name); err != nil {
		return it, errors.New(svops.ItemNameNeeded)
	}
	it.Label = strings.TrimSpace(ed.label.GetText())
	for _, t := range strings.Split(ed.tags.GetText(), ",") {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(it.Tags, t) {
			it.Tags = append(it.Tags, t)
		}
	}
	for _, line := range strings.Split(ed.attrs.GetText(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if k = strings.TrimSpace(k); !ok || k == "" {
			return it, fmt.Errorf("the attribute %q is not key=value", strings.TrimSpace(line))
		}
		if it.Attrs == nil {
			it.Attrs = map[string]string{}
		}
		it.Attrs[k] = strings.TrimSpace(v)
	}
	for _, fe := range ed.fields {
		v := fe.value()
		if len(v) == 0 && ed.orig == "" {
			continue // an unused field of the template
		}
		it.Fields = append(it.Fields, svrpc.Field{Name: fe.name, Type: fe.typ, Value: v})
	}
	return it, nil
}

// save stores the item: renaming it first if its name was changed.
func (ed *editor) save() {
	u := ed.u
	if ed.saving {
		return
	}
	it, err := ed.item()
	if err != nil {
		wipeItem(&it)
		u.say("%s", sentence(err.Error()))
		return
	}
	vault, orig, name := ed.vault, ed.orig, it.Name
	ed.saving = true
	renamed := false
	u.call(func(ctx context.Context, c *secretvault.Client) error {
		defer wipeItem(&it)
		if orig != "" && orig != name {
			if _, err := c.Rename(ctx, vault, orig, name); err != nil {
				return err
			}
			renamed = true
		}
		_, err := c.Put(ctx, vault, it)
		return err
	}, func(err error) {
		ed.saving = false
		if renamed {
			ed.orig = name
		}
		if err != nil {
			u.fail(err)
			return
		}
		if u.editor == ed {
			ed.close()
		}
		u.say("Saved %s", name)
		if vault == u.vault {
			u.cursor = name
			u.openItem(name, false)
			u.loadItems()
		}
	})
}

// close closes the editor, wiping what was typed into it.
func (ed *editor) close() {
	ed.wipe()
	if ed.u.editor == ed {
		ed.u.editor = nil
	}
	ed.u.closePage(pageDialog)
	ed.u.closePage(pageForm)
}

func (ed *editor) wipe() {
	for _, fe := range ed.fields {
		fe.wipe()
	}
}

// showGenerator shows the password generator. With use, its "Use" button
// hands the password over (to the editor); without, it offers to copy the
// password or to make a new item with it.
func (u *UI) showGenerator(use func([]byte)) {
	var pw []byte
	length, symbols := 24, true
	form := tview.NewForm()
	preview := newSecretInput("Password")
	preview.reveal = true
	regenerate := func() {
		p, err := svops.GeneratePassword(length, symbols)
		if err != nil {
			u.fail(err)
			return
		}
		clear(pw)
		pw = p
		preview.set(pw)
	}
	var id int
	done := func() {
		clear(pw)
		preview.wipe()
		u.closeDialog(id)
	}
	size := tview.NewInputField().SetLabel("Length").SetText(strconv.Itoa(length)).SetFieldWidth(5).
		SetAcceptanceFunc(tview.InputFieldInteger)
	size.SetChangedFunc(func(text string) {
		if n, err := strconv.Atoi(text); err == nil && n >= 8 && n <= 128 && n != length {
			length = n
			regenerate()
		}
	})
	sym := tview.NewCheckbox().SetLabel("Symbols").SetChecked(true)
	sym.SetChangedFunc(func(on bool) {
		symbols = on
		regenerate()
	})
	form.AddFormItem(size).AddFormItem(sym).AddFormItem(preview)
	preview.SetDisabled(true)
	if use != nil {
		form.AddButton("Use this password", func() {
			use(pw)
			done()
		})
	} else {
		form.AddButton("Copy", func() { u.copyValue(pw) })
		form.AddButton("New item with it", func() {
			p := append([]byte(nil), pw...)
			done()
			u.newItem(p)
			clear(p)
		})
	}
	form.AddButton("Make another", regenerate).AddButton("Close", done)
	form.SetCancelFunc(done)
	form.SetBorder(true).SetTitle(" Password generator — 8 to 128 characters ")
	regenerate()
	id = u.openDialog(centred(form, 64, 11), form, done)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
