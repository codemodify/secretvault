package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The parity matrix, docs/interfaces.md, against the CLI itself: every
// command of the commands table, and every subcommand its function picks
// by args[0], has a row there; no row names a command that is not; and
// every row says where the operation lives in the desktop and terminal
// managers, and how far each has got, or that the command is for other
// programs (and what a person's side of it is).

const matrixPath = "../../docs/interfaces.md"

// forPrograms are the commands that exist for other programs, not
// people: their rows carry the mark in both managers' cells.
var forPrograms = []string{"read", "run", "inject", "git-credential", "docker-credential", "age-plugin", "browser-host", clipCommand, "ci"}

const programsMark = "**for programs**"

// subAliases are spellings of one subcommand.
var subAliases = map[string]string{"ls": "list", "remove": "rm"}

func normalSub(s string) string {
	if a, ok := subAliases[s]; ok {
		return a
	}
	return s
}

// cliTree is the CLI's commands: for each, its subcommands, and theirs.
type cliTree map[string]map[string]map[string]bool

// readCLI reads the commands table and each command's subcommands from
// the package's sources.
func readCLI(t *testing.T) cliTree {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]*ast.FuncDecl{}
	var table *ast.CompositeLit
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if fd.Recv != nil {
					methods[fd.Name.Name] = fd
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "commands" {
							table, _ = as.Rhs[0].(*ast.CompositeLit)
						}
					}
					return true
				})
			}
		}
	}
	if table == nil {
		t.Fatal("no commands table in the sources")
	}
	tree := cliTree{clipCommand: {}}
	for _, e := range table.Elts {
		row, ok := e.(*ast.CompositeLit)
		if !ok || len(row.Elts) != 3 {
			t.Fatalf("a row of the commands table is not {name, summary, method}: %#v", e)
		}
		name := stringLit(row.Elts[0])
		sel, ok := row.Elts[2].(*ast.SelectorExpr)
		if name == "" || !ok || methods[sel.Sel.Name] == nil {
			t.Fatalf("the commands table's row %q names no method of cli", name)
		}
		subs := map[string]map[string]bool{}
		for sub, call := range subcommands(methods[sel.Sel.Name]) {
			nested := map[string]bool{}
			if m := methods[call]; m != nil && call != sel.Sel.Name {
				for s := range subcommands(m) {
					nested[s] = true
				}
			}
			subs[sub] = nested
		}
		tree[name] = subs
	}
	// The table read from the sources is the one the program has.
	var got, want []string
	for _, c := range commands {
		want = append(want, c.name)
	}
	for n := range tree {
		if n != clipCommand {
			got = append(got, n)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("the commands read from the sources, %v, are not the program's, %v", got, want)
	}
	return tree
}

func stringLit(e ast.Expr) string {
	if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
		s, _ := strconv.Unquote(bl.Value)
		return s
	}
	return ""
}

// isArgs0 reports whether e is args[0].
func isArgs0(e ast.Expr) bool {
	ix, ok := e.(*ast.IndexExpr)
	if !ok {
		return false
	}
	id, ok := ix.X.(*ast.Ident)
	return ok && id.Name == "args" && stringLitInt(ix.Index) == "0"
}

func stringLitInt(e ast.Expr) string {
	if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.INT {
		return bl.Value
	}
	return ""
}

// subcommands are the names a command's function picks by args[0] (in a
// switch, or compared with == and !=), normalised, each with the method
// its case hands the rest of the arguments to ("" when none).
func subcommands(fd *ast.FuncDecl) map[string]string {
	out := map[string]string{}
	add := func(s, call string) {
		if s == "" || strings.HasPrefix(s, "-") || s == "help" {
			return
		}
		s = normalSub(s)
		if out[s] == "" {
			out[s] = call
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SwitchStmt:
			if n.Tag == nil || !isArgs0(n.Tag) {
				return true
			}
			for _, st := range n.Body.List {
				cc := st.(*ast.CaseClause)
				call := ""
				for _, b := range cc.Body {
					ast.Inspect(b, func(m ast.Node) bool {
						ce, ok := m.(*ast.CallExpr)
						if !ok || call != "" {
							return call == ""
						}
						sel, ok := ce.Fun.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "c" {
							return true
						}
						for _, a := range ce.Args {
							if se, ok := a.(*ast.SliceExpr); ok {
								if id, ok := se.X.(*ast.Ident); ok && id.Name == "args" {
									call = sel.Sel.Name
								}
							}
						}
						return true
					})
				}
				for _, e := range cc.List {
					add(stringLit(e), call)
				}
			}
		case *ast.BinaryExpr:
			if n.Op != token.EQL && n.Op != token.NEQ {
				return true
			}
			switch {
			case isArgs0(n.X):
				add(stringLit(n.Y), "")
			case isArgs0(n.Y):
				add(stringLit(n.X), "")
			}
		}
		return true
	})
	return out
}

// matrixRow is a row of the parity matrix.
type matrixRow struct {
	line                     int
	cli, op, gui, guiState   string
	tui, tuiState            string
	commands                 [][]string // the commands its CLI cell names, as words
	guiPrograms, tuiPrograms bool
}

var (
	codeSpan = regexp.MustCompile("`([^`]+)`")
	cliWord  = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]*$`)
)

// splitRow splits a table row into its cells, "\|" being a | in a cell.
func splitRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteByte('|')
			i++
		case line[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(line[i])
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

// commandWords are the words of a command line after "secretvault" that
// name a command and its subcommands: up to the first flag, argument or
// placeholder.
func commandWords(s string) []string {
	fields := strings.Fields(s)
	if len(fields) == 0 || fields[0] != "secretvault" {
		return nil
	}
	var out []string
	for i, f := range fields[1:] {
		if !cliWord.MatchString(f) {
			break
		}
		if i > 0 {
			f = normalSub(f)
		}
		out = append(out, f)
	}
	return out
}

func readMatrix(t *testing.T) []matrixRow {
	t.Helper()
	b, err := os.ReadFile(matrixPath)
	if err != nil {
		t.Fatal(err)
	}
	header := []string{"CLI", "Operation", "GUI", "GUI state", "TUI", "TUI state"}
	var rows []matrixRow
	for i, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		cells := splitRow(line)
		if slices.Equal(cells, header) || strings.Trim(strings.Join(cells, ""), "- ") == "" {
			continue
		}
		if len(cells) != len(header) {
			t.Errorf("%s:%d: %d cells, not %d (%s)", matrixPath, i+1, len(cells), len(header), strings.Join(header, ", "))
			continue
		}
		r := matrixRow{line: i + 1, cli: cells[0], op: cells[1], gui: cells[2], guiState: cells[3], tui: cells[4], tuiState: cells[5]}
		for _, m := range codeSpan.FindAllStringSubmatch(r.cli, -1) {
			if w := commandWords(m[1]); len(w) > 0 {
				r.commands = append(r.commands, w)
			}
		}
		r.guiPrograms = strings.HasPrefix(r.gui, programsMark)
		r.tuiPrograms = strings.HasPrefix(r.tui, programsMark)
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no rows", matrixPath)
	}
	return rows
}

func TestEveryCommandHasARowInTheParityMatrix(t *testing.T) {
	tree := readCLI(t)
	rows := readMatrix(t)

	// What the CLI has, as word lists: commands, subcommands, theirs.
	var want [][]string
	for c, subs := range tree {
		want = append(want, []string{c})
		for s, nested := range subs {
			want = append(want, []string{c, s})
			for n := range nested {
				want = append(want, []string{c, s, n})
			}
		}
	}
	sort.Slice(want, func(i, j int) bool { return strings.Join(want[i], " ") < strings.Join(want[j], " ") })

	// Each has a row naming it (or a longer form of it).
	for _, w := range want {
		found := false
		for _, r := range rows {
			for _, c := range r.commands {
				if len(c) >= len(w) && slices.Equal(c[:len(w)], w) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("'secretvault %s' has no row in %s", strings.Join(w, " "), matrixPath)
		}
	}

	states := []string{"done", "partial", "missing"}
	for _, r := range rows {
		where := matrixPath + ":" + strconv.Itoa(r.line)
		if len(r.commands) == 0 {
			t.Errorf("%s: the CLI cell names no command: %q", where, r.cli)
			continue
		}
		// No row names what the CLI does not have.
		for _, c := range r.commands {
			subs, ok := tree[c[0]]
			switch {
			case !ok:
				t.Errorf("%s: there is no command %q", where, c[0])
			case len(c) >= 2 && len(subs) > 0:
				nested, ok := subs[c[1]]
				if !ok {
					t.Errorf("%s: %q has no subcommand %q", where, c[0], c[1])
				} else if len(c) >= 3 && len(nested) > 0 && !nested[c[2]] {
					t.Errorf("%s: '%s %s' has no subcommand %q", where, c[0], c[1], c[2])
				}
			}
		}
		if r.op == "" {
			t.Errorf("%s: no operation for %s", where, r.cli)
		}
		if strings.Trim(r.gui, "- ") == "" || strings.Trim(r.tui, "- ") == "" {
			t.Errorf("%s: %s needs a GUI place and a TUI place, or the %s mark", where, r.cli, programsMark)
		}
		if !slices.Contains(states, r.guiState) || !slices.Contains(states, r.tuiState) {
			t.Errorf("%s: states %q and %q, not one of %v", where, r.guiState, r.tuiState, states)
		}
		if r.guiPrograms != r.tuiPrograms {
			t.Errorf("%s: %s is %s in one manager's cell only", where, r.cli, programsMark)
		}
		programs := slices.Contains(forPrograms, r.commands[0][0])
		if programs != r.guiPrograms {
			t.Errorf("%s: %s: marked %s %v, but it is %v", where, r.cli, programsMark, r.guiPrograms, programs)
		}
		if r.guiPrograms && (len(strings.TrimSpace(strings.TrimPrefix(r.gui, programsMark))) < 3 || len(strings.TrimSpace(strings.TrimPrefix(r.tui, programsMark))) < 3) {
			t.Errorf("%s: %s is for programs: say what a person's side of it is, in each manager", where, r.cli)
		}
	}
}
