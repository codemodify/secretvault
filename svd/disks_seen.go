package svd

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svrpc"
)

// The disks the daemon has seen, vault by vault (container.known). A
// disk's key is an item, so a locked vault's disks cannot be listed from
// the vault: the daemon remembers, in disks.json in its data directory,
// the image files container.list, create, open and passwd named for each
// vault, and forgets one when container.delete deletes it, a listing of
// its vault no longer names it, or the vault is forgotten. Only vault
// names and file paths are kept there, never a key or an item's name:
// which files on this computer are disks of which vault, as the files on
// the drive show anyway, to the person whose data directory it is.

// seenFileName is the file in the data directory.
const seenFileName = "disks.json"

// seenDisks is the daemon's memory of disks, loaded on first use.
type seenDisks struct {
	mu     sync.Mutex
	loaded bool
	vaults map[string][]string // by vault name: canonical image paths, sorted
}

// seenFile is disks.json.
type seenFile struct {
	Vaults map[string][]string `json:"vaults"`
}

// seenUpdate changes the disks remembered for vault with change, and
// writes them down if that changed anything.
func (d *Daemon) seenUpdate(vault string, change func(paths []string) []string) {
	s := &d.ctr.seen
	s.mu.Lock()
	defer s.mu.Unlock()
	d.seenLoad()
	old := s.vaults[vault]
	paths := change(slices.Clone(old))
	for i := range paths {
		paths[i] = svcontainer.Canonical(paths[i])
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	if slices.Equal(paths, old) {
		return
	}
	if len(paths) == 0 {
		delete(s.vaults, vault)
	} else {
		s.vaults[vault] = paths
	}
	b, err := json.MarshalIndent(seenFile{Vaults: s.vaults}, "", "  ")
	if err == nil {
		err = writeAtomic(filepath.Join(d.home, seenFileName), append(b, '\n'))
	}
	if err != nil {
		d.opts.Log("remembering the disks seen: " + err.Error())
	}
}

// seenLoad reads disks.json, once. The caller holds seen.mu.
func (d *Daemon) seenLoad() {
	s := &d.ctr.seen
	if s.loaded {
		return
	}
	s.loaded, s.vaults = true, map[string][]string{}
	b, err := os.ReadFile(filepath.Join(d.home, seenFileName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			d.opts.Log("reading the disks seen: " + err.Error())
		}
		return
	}
	var f seenFile
	if err := json.Unmarshal(b, &f); err != nil {
		d.opts.Log("reading the disks seen: " + err.Error())
		return
	}
	for v, paths := range f.Vaults {
		var ok []string
		for _, p := range paths {
			if filepath.IsAbs(p) {
				ok = append(ok, p)
			}
		}
		if len(ok) > 0 {
			slices.Sort(ok)
			s.vaults[v] = slices.Compact(ok)
		}
	}
}

// sawDisk remembers path as a disk of vault.
func (d *Daemon) sawDisk(vault, path string) {
	if vault == "" || path == "" {
		return
	}
	d.seenUpdate(vault, func(paths []string) []string { return append(paths, path) })
}

// sawDisks remembers paths as the disks of vault, and no others: what a
// listing of the vault found.
func (d *Daemon) sawDisks(vault string, paths []string) {
	d.seenUpdate(vault, func([]string) []string { return slices.Clone(paths) })
}

// lostDisk forgets path as a disk of vault.
func (d *Daemon) lostDisk(vault, path string) {
	path = svcontainer.Canonical(path)
	d.seenUpdate(vault, func(paths []string) []string {
		return slices.DeleteFunc(paths, func(p string) bool { return svcontainer.Canonical(p) == path })
	})
}

// forgetDisks forgets every disk of vault: it is forgotten, or the name
// is a new vault's.
func (d *Daemon) forgetDisks(vault string) {
	d.seenUpdate(vault, func([]string) []string { return nil })
}

// seenOf are the disks remembered for vault.
func (d *Daemon) seenOf(vault string) []string {
	s := &d.ctr.seen
	s.mu.Lock()
	defer s.mu.Unlock()
	d.seenLoad()
	return slices.Clone(s.vaults[vault])
}

// diskStatus is where each attached image is, by its file, when this
// system can say (known).
func (d *Daemon) diskStatus(ctx context.Context) (status map[string]svcontainer.Status, known bool) {
	status = map[string]svcontainer.Status{}
	disks, err := d.disks()
	if err != nil {
		return status, false
	}
	all, err := disks.All(ctx)
	if err != nil {
		return status, false
	}
	for _, s := range all {
		if cur, seen := status[s.Image]; !seen || !cur.Mounted() {
			status[s.Image] = s
		}
	}
	return status, true
}

// statusOf is the image at path's entry in status: by its name, or by any
// other name of the same file (a hard link, a path through a link).
func statusOf(status map[string]svcontainer.Status, path string, fi os.FileInfo) svcontainer.Status {
	if s, ok := status[svcontainer.Canonical(path)]; ok {
		return s
	}
	if fi == nil {
		return svcontainer.Status{}
	}
	for img, s := range status {
		if st, err := os.Stat(img); err == nil && os.SameFile(st, fi) {
			return s
		}
	}
	return svcontainer.Status{}
}

// listContainers lists the containers whose keys mv holds, and
// remembers their files.
func (d *Daemon) listContainers(mv *managedVault, status map[string]svcontainer.Status, known bool) ([]svrpc.ContainerInfo, error) {
	entries, err := mv.v.List("")
	if err != nil {
		return nil, err
	}
	out := []svrpc.ContainerInfo{}
	var paths []string
	for _, e := range entries {
		e.Item.Wipe()
		if e.Item.Kind != kindContainer {
			continue
		}
		path := e.Item.Attrs[attrImage]
		fi, err := os.Stat(path)
		ci := containerInfo(mv.cfg.Name, e.Item.Name, path, e.Item.Attrs[attrUUID], e.Item.Attrs[attrPassSlot] != "", statusOf(status, path, fi), known)
		if errors.Is(err, fs.ErrNotExist) && !diskAttached(ci.State) {
			ci.State = "missing"
		}
		out = append(out, ci)
		if filepath.IsAbs(path) {
			paths = append(paths, path)
		}
	}
	d.sawDisks(mv.cfg.Name, paths)
	return out, nil
}

// diskAttached reports whether a state says the image is in use as a disk.
func diskAttached(state string) bool {
	return state == "mounted" || state == "unlocked" || state == "attached"
}

// rememberedDisks are mv's disks as the daemon remembers them: their
// files, their LUKS UUIDs (the header says, without the key) and their
// states, with nothing of the items that keep their keys.
func (d *Daemon) rememberedDisks(mv *managedVault, status map[string]svcontainer.Status, known bool) []svrpc.ContainerInfo {
	var out []svrpc.ContainerInfo
	locked := mv.v.Locked()
	for _, path := range d.seenOf(mv.cfg.Name) {
		fi, err := os.Stat(path)
		st := statusOf(status, path, fi)
		uuid := ""
		if err == nil {
			if h, err := svcontainer.Inspect(path); err == nil {
				uuid = h.UUID()
			}
		}
		ci := containerInfo(mv.cfg.Name, "", path, uuid, false, st, known)
		if errors.Is(err, fs.ErrNotExist) && !diskAttached(ci.State) {
			ci.State = "missing"
		}
		ci.Locked = locked
		out = append(out, ci)
	}
	return out
}

func init() {
	registerMethod(svrpc.MContainerKnown, (*Daemon).containerKnown)
}

// containerKnown lists every vault's disks: an unlocked vault's from the
// vault, asked about as container.list is, and a locked one's (or one
// this program may not list) as the daemon remembers them. It never
// unlocks a vault.
func (d *Daemon) containerKnown(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p struct{}
	if err := decode(&p); err != nil {
		return nil, err
	}
	d.mu.Lock()
	var vaults []*managedVault
	for _, mv := range d.vaults {
		if mv.v != nil { // a vault whose folder is missing has no disks to show
			vaults = append(vaults, mv)
		}
	}
	d.mu.Unlock()
	sort.Slice(vaults, func(i, j int) bool { return vaults[i].cfg.Name < vaults[j].cfg.Name })

	status, known := d.diskStatus(ctx)
	out := []svrpc.ContainerInfo{}
	for _, mv := range vaults {
		if !mv.v.Locked() {
			why := describeRequest(cl, mv, "", svbroker.OpList)
			err := d.decide(ctx, cl, mv, "", "", svbroker.OpList, why, false, false, d.recorder(cl, mv, "", svbroker.OpList))
			var list []svrpc.ContainerInfo
			if err == nil {
				list, err = d.listContainers(mv, status, known)
			}
			if err == nil {
				out = append(out, list...)
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Not this program's to list, or locked meanwhile: as it is
			// remembered, as for a locked one.
		}
		out = append(out, d.rememberedDisks(mv, status, known)...)
	}
	return out, nil
}
