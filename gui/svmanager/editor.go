package svmanager

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// The item editor: a page in place of the item, for a new item or a
// changed one. Secret values are typed into SecretFields, which keep them
// out of Go strings.

// editor is the open editor.
type editor struct {
	m     *Manager
	vault string
	orig  string // the name of the item being changed; "" for a new one

	page    *page
	kind    *widgets.ComboBox
	kinds   []string
	name    *widgets.TextField
	label   *widgets.TextField
	tags    *widgets.TextField
	attrs   *widgets.TextArea
	fields  []*fieldEditor
	grid    *widgets.Grid
	problem *widgets.Label
	reveal  *widgets.Button
	shown   bool // secrets are revealed
	touched bool // a field was typed into: a new item keeps its fields when the kind changes
	saving  bool

	lastSecret *widgets.SecretField // the secret field last typed into, for the generator
}

// fieldEditor is one field in the editor.
type fieldEditor struct {
	name, typ string
	input     *widgets.TextField   // text, url, email
	area      *widgets.TextArea    // json, notes, and text of several lines
	secret    *widgets.SecretField // concealed, otp, and keys that fit one line
	kept      []byte               // a value kept as it is: binary, and keys of several lines
	remove    *widgets.Button
}

func (fe *fieldEditor) value() []byte {
	switch {
	case fe.secret != nil:
		return fe.secret.Bytes()
	case fe.area != nil:
		return []byte(fe.area.Text)
	case fe.input != nil:
		return []byte(fe.input.Text)
	}
	return bytes.Clone(fe.kept)
}

func (fe *fieldEditor) wipe() {
	if fe.secret != nil {
		fe.secret.Wipe()
	}
	clear(fe.kept)
}

// fieldTypes are the types a new field may have.
var fieldTypes = []string{svcore.FieldText, svcore.FieldConcealed, svcore.FieldURL, svcore.FieldEmail,
	svcore.FieldOTP, svcore.FieldJSON, svcore.FieldKey}

// templates are the fields a new item of each kind starts with.
var templates = map[string][][2]string{
	"login":    {{"username", svcore.FieldText}, {"password", svcore.FieldConcealed}, {"url", svcore.FieldURL}, {"otp", svcore.FieldOTP}},
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

// newItem opens the editor on a new login, with generated (if any) as its
// password.
func (m *Manager) newItem(generated []byte) {
	if m.vault == "" || m.gone {
		m.say("There is no vault to put an item in.")
		return
	}
	if v := m.vaultInfo(m.vault); v != nil && v.Locked {
		m.say("Vault %s is locked: Ctrl+U unlocks it.", m.vault)
		return
	}
	ed := m.openEditor(nil)
	if generated != nil {
		ed.useGenerated(generated)
	}
}

// editItem opens the editor on the target item.
func (m *Manager) editItem() {
	if m.editor != nil {
		return
	}
	m.withItem(func(e *svrpc.Entry) { m.openEditor(e) })
}

// openEditor puts the editor up, on a copy of e (nil for a new item).
func (m *Manager) openEditor(e *svrpc.Entry) *editor {
	if m.editor != nil {
		m.editor.close()
	}
	ed := &editor{m: m, vault: m.vault}
	m.editor = ed
	it := svrpc.Item{Kind: "login"}
	if e != nil {
		// e may be the open item, whose values are wiped when it is
		// closed below: the fields take their copies first.
		it, ed.orig = e.Item, e.Item.Name
	}

	ed.kinds = slices.Clone(svcore.Kinds)
	if !slices.Contains(ed.kinds, it.Kind) {
		ed.kinds = append(ed.kinds, it.Kind)
	}
	ed.kind = widgets.NewComboBox(ed.kinds, slices.Index(ed.kinds, it.Kind), func(i int) { ed.kindChanged(ed.kinds[i]) })
	ed.name = widgets.NewTextField(it.Name, "a path, like web/example.com", nil)
	ed.label = widgets.NewTextField(it.Label, "a title for people (optional)", nil)
	ed.tags = widgets.NewTextField(strings.Join(it.Tags, ", "), "comma-separated (optional)", nil)
	var attrs []string
	for _, k := range sortedKeys(it.Attrs) {
		attrs = append(attrs, k+"="+it.Attrs[k])
	}
	ed.attrs = widgets.NewTextArea(strings.Join(attrs, "\n"), "key=value, one per line (optional)", nil)
	ed.attrs.MinRows = 2

	form := widgets.NewForm()
	form.AddRow("Kind", ed.kind)
	form.AddRow("Name", ed.name)
	form.AddRow("Label", ed.label)
	form.AddRow("Tags", ed.tags)
	form.AddRow("Attributes", ed.attrs)

	ed.grid = widgets.NewGrid()
	ed.grid.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1), widgets.Auto(), widgets.Auto()}
	ed.grid.ColGap, ed.grid.RowGap = 12, 6
	if e == nil {
		ed.setTemplate(it.Kind)
	} else {
		for _, f := range it.Fields {
			ed.addField(f.Name, f.Type, f.Value)
		}
		ed.layoutFields()
	}
	m.closeItem()

	ed.problem = m.tint(widgets.NewLabel(""), toneDanger)
	ed.problem.Wrap = true
	save := tip(widgets.NewButton("Save", ed.save), "Ctrl+S")
	save.Primary = true
	ed.reveal = tip(widgets.NewButton("Show secrets", ed.toggleReveal), "Ctrl+R")
	buttons := widgets.NewWrap(
		save,
		tip(widgets.NewButton("Add field…", ed.askField), "Ctrl+Shift+N"),
		tip(widgets.NewButton("Generate password…", func() { m.showGenerator(ed.useGenerated) }), "Ctrl+G"),
		ed.reveal,
		tip(widgets.NewButton("Cancel", ed.close), "Escape"),
	)

	title := "New item in " + m.vault
	if e != nil {
		title = "Edit " + e.Item.Name
	}
	col := widgets.NewColumn(heading(title), form, section(m, "Fields"), ed.grid, ed.problem, buttons).WithGap(gap)
	ed.page = newPage(pageEditor, widgets.NewScrollView(col), ed.key)
	m.ui.pane.Set(ed.page)
	if e == nil {
		m.win.RequestFocus(ed.name)
	} else {
		m.win.RequestFocus(ed.label)
	}
	m.enableMenus()
	return ed
}

// key handles the editor's keys.
func (ed *editor) key(e widget.KeyEvent) bool {
	switch {
	case e.Key == platform.KeyS && e.Mods.Ctrl():
		ed.save()
	case e.Key == platform.KeyR && e.Mods.Ctrl():
		ed.toggleReveal()
	case e.Key == platform.KeyG && e.Mods.Ctrl():
		ed.m.showGenerator(ed.useGenerated)
	case e.Key == platform.KeyN && e.Mods.Ctrl() && e.Mods.Shift():
		ed.askField()
	case e.Key == platform.KeyEscape:
		ed.close()
	default:
		return false
	}
	return true
}

// addField adds a field, holding a copy of value.
func (ed *editor) addField(name, typ string, value []byte) *fieldEditor {
	fe := &fieldEditor{name: name, typ: typ}
	switch {
	case (typ == svcore.FieldConcealed || typ == svcore.FieldOTP || typ == svcore.FieldKey) && oneLine(value):
		s := widgets.NewSecretField("")
		s.Mono = true
		s.Reveal = ed.shown
		setSecret(s, value)
		s.OnChange = func(f *widgets.SecretField) {
			ed.touched = true
			ed.lastSecret = f
		}
		s.SetAccessibleName(name)
		fe.secret = s
	case typ == svcore.FieldConcealed || typ == svcore.FieldOTP || typ == svcore.FieldKey || typ == svcore.FieldBinary:
		// A key of several lines (PEM, OpenSSH) does not fit a one-line
		// secret field, and uitoolkit has no secret text area: it is kept
		// as it is, and can be replaced from a file.
		fe.kept = bytes.Clone(value)
	case typ == svcore.FieldJSON || bytes.ContainsRune(value, '\n') || name == "note" || name == "notes":
		a := widgets.NewTextArea(string(value), "", func(string) { ed.touched = true })
		a.MinRows = 3
		a.Mono = typ == svcore.FieldJSON
		a.SetAccessibleName(name)
		fe.area = a
	default:
		in := widgets.NewTextField(string(value), "", func(string) { ed.touched = true })
		in.SetAccessibleName(name)
		fe.input = in
	}
	fe.remove = widgets.NewButton("Remove", func() { ed.removeField(fe) })
	fe.remove.Tip = "Remove the " + name + " field"
	ed.fields = append(ed.fields, fe)
	return fe
}

// oneLine reports whether a value fits a one-line secret field: no line
// breaks, no control characters, and valid UTF-8.
func oneLine(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// setSecret puts value into a secret field. uitoolkit's SecretField takes
// its contents only as typing, so it is given them one rune at a time,
// through the path a key press takes; nothing becomes a string.
func setSecret(f *widgets.SecretField, value []byte) {
	f.Wipe()
	for len(value) > 0 {
		r, n := utf8.DecodeRune(value)
		value = value[n:]
		f.TextInput(r)
	}
}

// layoutFields lays the fields out again, after one was added or removed.
func (ed *editor) layoutFields() {
	g := ed.grid
	g.ClearChildren()
	for i, fe := range ed.fields {
		g.Place(widgets.NewLabel(fe.name), i, 0)
		var value widget.Component
		switch {
		case fe.secret != nil:
			value = fe.secret
		case fe.area != nil:
			value = fe.area
		case fe.input != nil:
			value = fe.input
		default:
			replace := widgets.NewButton("Replace from file…", func() { ed.replaceFromFile(fe) })
			value = widgets.NewRow(ed.m.muted(fmt.Sprintf("%s, kept as it is", size(int64(len(fe.kept))))), replace).WithGap(gap).WithAlign(layout.AlignCenter)
		}
		g.Place(value, i, 1)
		g.Place(ed.m.muted(fe.typ), i, 2)
		g.Place(fe.remove, i, 3)
	}
	g.RequestLayout()
	g.Invalidate()
}

// replaceFromFile replaces a kept value with a file's contents, read
// straight into bytes.
func (ed *editor) replaceFromFile(fe *fieldEditor) {
	ed.m.pickFile(false, "", func(path string) {
		if path == "" {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			ed.problem.SetText(sentence(err.Error()))
			return
		}
		clear(fe.kept)
		fe.kept = b
		ed.touched = true
		ed.layoutFields()
	})
}

// removeField takes a field out, wiping it.
func (ed *editor) removeField(fe *fieldEditor) {
	i := slices.Index(ed.fields, fe)
	if i < 0 {
		return
	}
	fe.wipe()
	if ed.lastSecret == fe.secret {
		ed.lastSecret = nil
	}
	ed.fields = slices.Delete(ed.fields, i, i+1)
	ed.touched = true
	ed.layoutFields()
	// The keyboard was on the button that went with the field: it goes to
	// the field that took its place, else back to the name.
	var next widget.Component = ed.name
	if len(ed.fields) > 0 {
		next = ed.fields[min(i, len(ed.fields)-1)].focusable(ed.name)
	}
	ed.m.win.RequestFocus(next)
}

// focusable is the widget that takes the keyboard for this field, or
// fallback when it has none (a value kept as it is).
func (fe *fieldEditor) focusable(fallback widget.Component) widget.Component {
	switch {
	case fe.secret != nil:
		return fe.secret
	case fe.area != nil:
		return fe.area
	case fe.input != nil:
		return fe.input
	}
	return fallback
}

// setTemplate replaces the fields with the ones a new item of kind starts
// with.
func (ed *editor) setTemplate(kind string) {
	for _, fe := range ed.fields {
		fe.wipe()
	}
	ed.fields, ed.lastSecret = nil, nil
	t, ok := templates[kind]
	if !ok {
		t = templates["generic"]
	}
	for _, f := range t {
		ed.addField(f[0], f[1], nil)
	}
	ed.touched = false
	ed.layoutFields()
}

// kindChanged gives a new, untouched item the fields of its new kind.
func (ed *editor) kindChanged(kind string) {
	if ed.orig == "" && !ed.touched {
		ed.setTemplate(kind)
	}
}

func (ed *editor) toggleReveal() {
	ed.shown = !ed.shown
	for _, fe := range ed.fields {
		if fe.secret != nil {
			fe.secret.Reveal = ed.shown
			fe.secret.Invalidate()
		}
	}
	ed.reveal.Text = "Show secrets"
	if ed.shown {
		ed.reveal.Text = "Hide secrets"
	}
	ed.reveal.RequestLayout()
	ed.m.syncCapture()
	ed.reveal.Invalidate()
}

// hideSecrets masks every secret field again (the window is going to the
// tray).
func (ed *editor) hideSecrets() {
	if ed.shown {
		ed.toggleReveal()
	}
}

// useGenerated puts a generated password in the secret field last typed
// into, else the item's password field, else a new one.
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
			if fe.typ == svcore.FieldConcealed && fe.secret != nil && target == nil {
				target = fe.secret
			}
		}
	}
	if target == nil {
		target = ed.addField("password", svcore.FieldConcealed, nil).secret
		ed.layoutFields()
	}
	setSecret(target, pw)
	ed.touched = true
	ed.lastSecret = target
}

// askField asks for a new field's name and type.
func (ed *editor) askField() {
	m := ed.m
	name := widgets.NewTextField("", "", nil)
	typ := widgets.NewComboBox(fieldTypes, 0, nil)
	problem := m.tint(widgets.NewLabel(""), toneDanger)
	form := widgets.NewForm()
	form.AddRow("Name", name)
	form.AddRow("Type", typ)
	var d *dialog
	add := widgets.NewButton("Add", nil)
	add.OnClick = func() {
		n := strings.TrimSpace(name.Text)
		if n == "" {
			problem.SetText("Give the field a name.")
			return
		}
		for _, fe := range ed.fields {
			if fe.name == n {
				problem.SetText("The item has a field called " + n + " already.")
				return
			}
		}
		d.Close()
		fe := ed.addField(n, fieldTypes[max(0, typ.Selected)], nil)
		ed.touched = true
		ed.layoutFields()
		m.win.RequestFocus(fe.focusable(ed.name))
	}
	name.OnSubmit = func(string) { add.OnClick() }
	buttons := widgets.NewButtonBox().AddButton(add, widgets.RoleAccept).
		AddButton(widgets.NewButton("Cancel", func() { d.Close() }), widgets.RoleReject)
	d = m.showDialog("Add a field", widgets.NewColumn(form, problem).WithGap(gap), buttons, name, nil)
}

// item reads the form. The caller wipes the fields' values.
func (ed *editor) item() (svrpc.Item, error) {
	var it svrpc.Item
	it.Kind = ed.kinds[max(0, ed.kind.Selected)]
	it.Name = strings.TrimSpace(ed.name.Text)
	if err := svcore.CheckName(it.Name); err != nil {
		return it, fmt.Errorf("give the item a name made of path segments, like web/example.com")
	}
	it.Label = strings.TrimSpace(ed.label.Text)
	for _, t := range strings.Split(ed.tags.Text, ",") {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(it.Tags, t) {
			it.Tags = append(it.Tags, t)
		}
	}
	for _, line := range strings.Split(ed.attrs.Text, "\n") {
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
	m := ed.m
	if ed.saving {
		return
	}
	it, err := ed.item()
	if err != nil {
		wipeItem(&it)
		ed.problem.SetText(sentence(err.Error()))
		return
	}
	ed.problem.SetText("")
	vault, orig, name := ed.vault, ed.orig, it.Name
	ed.saving = true
	renamed := false
	m.call(func(ctx context.Context, c *secretvault.Client) error {
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
			ed.problem.SetText(m.describe(err))
			m.fail(err)
			return
		}
		if m.editor == ed {
			ed.close()
		}
		m.say("Saved %s.", name)
		if vault == m.vault {
			m.cursor = name
			m.openItem(name, false)
			m.loadItems()
		}
	})
}

// close closes the editor, wiping what was typed into it.
func (ed *editor) close() {
	ed.wipe()
	if ed.m.editor != ed {
		return
	}
	ed.m.editor = nil
	if ed.m.ui.pane.Page() == widget.Component(ed.page) {
		ed.m.showSelected()
	}
	ed.m.win.RequestFocus(ed.m.ui.items)
	ed.m.enableMenus()
	ed.m.syncCapture()
}

func (ed *editor) wipe() {
	for _, fe := range ed.fields {
		fe.wipe()
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
