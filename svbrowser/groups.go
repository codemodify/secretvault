package svbrowser

import (
	"sort"
	"strings"
)

// Group is a KeePass group as the extension sees it. secretvault has no
// groups: its folders are the path prefixes of item names ("web" and
// "web/shops" for "web/shops/example.com"), and those are what the
// extension is shown.
type Group struct {
	Name     string  `json:"name"`
	UUID     string  `json:"uuid"`
	Children []Group `json:"children"`
}

// Folders lists the folders item names are in: every path prefix of each
// name, without the root.
func Folders(names []string) []string {
	seen := map[string]bool{}
	for _, n := range names {
		segs := strings.Split(n, "/")
		for i := 1; i < len(segs); i++ {
			seen[strings.Join(segs[:i], "/")] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Tree builds the group tree of folders, under a root group named
// rootName. id gives each folder's UUID, the root being "".
func Tree(rootName string, folders []string, id func(folder string) string) Group {
	root := Group{Name: rootName, UUID: id(""), Children: []Group{}}
	for _, f := range folders {
		insert(&root, "", strings.Split(f, "/"), id)
	}
	sortTree(&root)
	return root
}

func insert(g *Group, prefix string, segs []string, id func(string) string) {
	if len(segs) == 0 || segs[0] == "" {
		return
	}
	p := segs[0]
	if prefix != "" {
		p = prefix + "/" + segs[0]
	}
	for i := range g.Children {
		if g.Children[i].Name == segs[0] {
			insert(&g.Children[i], p, segs[1:], id)
			return
		}
	}
	g.Children = append(g.Children, Group{Name: segs[0], UUID: id(p), Children: []Group{}})
	insert(&g.Children[len(g.Children)-1], p, segs[1:], id)
}

func sortTree(g *Group) {
	sort.Slice(g.Children, func(i, j int) bool { return g.Children[i].Name < g.Children[j].Name })
	for i := range g.Children {
		sortTree(&g.Children[i])
	}
}

// CleanFolder reads a group path the extension names ("Work/Sites", with
// or without slashes around it) as a folder: "" for the root, false when
// it cannot be one.
func CleanFolder(p string) (string, bool) {
	var segs []string
	for _, s := range strings.Split(p, "/") {
		s = strings.TrimSpace(s)
		switch {
		case s == "":
			continue
		case s == "." || s == ".." || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
			return "", false
		}
		segs = append(segs, s)
	}
	f := strings.Join(segs, "/")
	return f, len(f) <= 512
}
