package svserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svstore"
)

// One vault on the server, in its own directory:
//
//	<root>/vaults/<vault>/devices.json   the enrolled device keys
//	<root>/vaults/<vault>/changes.log    the change log (log.go)
//	<root>/vaults/<vault>/emergency.json its emergency grants (emergency.go), if any
//	<root>/vaults/<vault>/files/...      the vault's files, as a client has them
//
// A vault exists once devices.json does. The files are an svstore.Dir, so
// each appears whole or not at all.

const (
	devicesFile = "devices.json"
	logFile     = "changes.log"
	filesDir    = "files"

	devicesFormat = "secretvault-server/v1/devices"
)

var (
	errConflict   = errors.New("different contents are already stored under that name")
	errGone       = errors.New("that keyslot was removed, and a removed keyslot cannot come back")
	errNoFile     = errors.New("no such file")
	errLastDevice = errors.New("that is the vault's only device")
	errNoDevice   = errors.New("no such device")
	errTooMany    = errors.New("too many enrolment codes are outstanding; use or let one expire first")
)

type fileRec struct {
	seq  uint64
	size int64
	sum  string
}

type vault struct {
	name  string
	dir   string
	files *svstore.Dir
	meta  *svstore.Dir

	mu      sync.Mutex
	log     *changeLog
	current map[string]fileRec
	removed map[string]bool // keyslots once here and removed
	devices []Device
	seen    map[string]time.Time
	codes   map[[32]byte]pendingCode // by the SHA-256 of the code
	grants  []*grantRec              // emergency grants (emergency.go), oldest first

	// notify is closed (and replaced) whenever a change is logged, waking
	// every long poll.
	notify chan struct{}
}

type devicesDoc struct {
	Format  string   `json:"format"`
	Devices []Device `json:"devices"`
}

// loadVault opens a vault's directory: its devices, its log, and the
// files, reconciling the log with what is on disk.
func loadVault(name, dir string, logf func(string)) (*vault, error) {
	meta, err := svstore.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	files, err := svstore.OpenDir(filepath.Join(dir, filesDir))
	if err != nil {
		return nil, err
	}
	v := &vault{
		name: name, dir: dir, files: files, meta: meta,
		current: map[string]fileRec{}, removed: map[string]bool{},
		seen: map[string]time.Time{}, codes: map[[32]byte]pendingCode{},
		notify: make(chan struct{}),
	}
	if b, err := meta.Read(devicesFile); err == nil {
		var doc devicesDoc
		if err := json.Unmarshal(b, &doc); err != nil || doc.Format != devicesFormat {
			return nil, fmt.Errorf("svserver: %s/%s is damaged", dir, devicesFile)
		}
		v.devices = doc.Devices
	} else if !errors.Is(err, svstore.ErrNotExist) {
		return nil, err
	}
	if v.grants, err = loadGrants(meta, dir); err != nil {
		return nil, err
	}
	if v.log, err = openLog(filepath.Join(dir, logFile)); err != nil {
		return nil, err
	}
	for _, c := range v.log.entries {
		v.track(c)
	}
	if err := v.reconcile(logf); err != nil {
		v.log.close()
		return nil, err
	}
	return v, nil
}

// track applies a logged change to what the vault holds now.
func (v *vault) track(c Change) {
	switch c.Op {
	case OpEvent:
		return // not a file
	case OpCreate:
		v.current[c.Name] = fileRec{seq: c.Seq, size: c.Size, sum: c.SHA256}
		delete(v.removed, c.Name)
		return
	}
	delete(v.current, c.Name)
	if k, _ := ClassifyName(c.Name); k == Slot {
		v.removed[c.Name] = true
	}
}

// reconcile logs whatever a crash left out: a file stored whose change was
// never written, or a file gone whose removal was not. It runs when a
// vault is loaded, before anyone can ask it anything.
func (v *vault) reconcile(logf func(string)) error {
	names, err := v.files.List("")
	if err != nil {
		return err
	}
	onDisk := make(map[string]bool, len(names))
	for _, n := range names {
		if _, err := ClassifyName(n); err != nil {
			logf(fmt.Sprintf("vault %s: ignoring stray file %s", v.name, n))
			continue
		}
		onDisk[n] = true
		if _, ok := v.current[n]; ok {
			continue
		}
		data, err := v.files.Read(n)
		if err != nil {
			return err
		}
		if _, err := v.logChange(Change{Op: OpCreate, Name: n, Size: int64(len(data)), SHA256: sum(data)}); err != nil {
			return err
		}
	}
	var gone []string
	for n := range v.current {
		if !onDisk[n] {
			gone = append(gone, n)
		}
	}
	sort.Strings(gone)
	for _, n := range gone {
		if _, err := v.logChange(Change{Op: OpRemove, Name: n}); err != nil {
			return err
		}
	}
	return nil
}

func sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// logChange appends to the log, tracks the change and wakes long polls.
// The caller holds v.mu (or is loading the vault).
func (v *vault) logChange(c Change) (Change, error) {
	c, err := v.log.append(c)
	if err != nil {
		return Change{}, err
	}
	v.track(c)
	close(v.notify)
	v.notify = make(chan struct{})
	return c, nil
}

// put stores a new file. Storing the same bytes again is not an error:
// created is false and seq is the change that first stored them.
func (v *vault) put(name string, data []byte) (seq uint64, created bool, err error) {
	s := sum(data)
	v.mu.Lock()
	defer v.mu.Unlock()
	if rec, ok := v.current[name]; ok {
		if rec.sum != s {
			return 0, false, errConflict
		}
		return rec.seq, false, nil
	}
	if v.removed[name] {
		return 0, false, errGone
	}
	if err := v.files.Create(name, data); errors.Is(err, svstore.ErrExist) {
		// Stored, but its change was not logged (a failure after the file
		// was written): log it now if the bytes are the same.
		old, rerr := v.files.Read(name)
		if rerr != nil {
			return 0, false, rerr
		}
		if !bytes.Equal(old, data) {
			return 0, false, errConflict
		}
	} else if err != nil {
		return 0, false, err
	}
	c, err := v.logChange(Change{Op: OpCreate, Name: name, Size: int64(len(data)), SHA256: s})
	if err != nil {
		return 0, false, err
	}
	return c.Seq, true, nil
}

// remove deletes a file (only ever a keyslot) and logs it.
func (v *vault) remove(name string) (uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.current[name]; !ok {
		return 0, errNoFile
	}
	if err := v.files.Remove(name); err != nil {
		return 0, err
	}
	c, err := v.logChange(Change{Op: OpRemove, Name: name})
	if err != nil {
		return 0, err
	}
	return c.Seq, nil
}

// changes returns what was logged after seq, and a channel closed at the
// next change, for waiting when there is nothing yet.
func (v *vault) changes(after uint64, limit int) (Changes, <-chan struct{}) {
	v.mu.Lock()
	defer v.mu.Unlock()
	list, more := v.log.after(after, limit)
	if list == nil {
		list = []Change{}
	}
	return Changes{Log: v.log.id, Latest: v.log.latest(), Changes: list, More: more}, v.notify
}

// Devices.

func (v *vault) exists() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.devices) > 0
}

func (v *vault) hasDevice(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.findDevice(key) >= 0
}

func (v *vault) findDevice(key string) int {
	for i, d := range v.devices {
		if d.Key == key {
			return i
		}
	}
	return -1
}

func (v *vault) sawDevice(key string, now time.Time) {
	v.mu.Lock()
	if v.findDevice(key) >= 0 { // not a trustee's
		v.seen[key] = now
	}
	v.mu.Unlock()
}

// saveDevices writes devices.json; on failure the old list is kept.
func (v *vault) saveDevices(devices []Device) error {
	b, err := json.MarshalIndent(devicesDoc{Format: devicesFormat, Devices: devices}, "", "  ")
	if err != nil {
		return err
	}
	if err := v.meta.Write(devicesFile, append(b, '\n')); err != nil {
		return err
	}
	v.devices = devices
	return nil
}

// addDevice enrols a key. Adding one already enrolled changes nothing.
func (v *vault) addDevice(d Device) (added bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.findDevice(d.Key) >= 0 {
		return false, nil
	}
	return true, v.saveDevices(append(append([]Device(nil), v.devices...), d))
}

func (v *vault) removeDevice(key string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findDevice(key)
	if i < 0 {
		return errNoDevice
	}
	if len(v.devices) == 1 {
		return errLastDevice
	}
	if err := v.saveDevices(append(append([]Device(nil), v.devices[:i]...), v.devices[i+1:]...)); err != nil {
		return err
	}
	delete(v.seen, key)
	return nil
}

func (v *vault) listDevices() []Device {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Device, len(v.devices))
	for i, d := range v.devices {
		if t, ok := v.seen[d.Key]; ok {
			d.LastSeen = &t
		}
		out[i] = d
	}
	return out
}

// Enrolment codes live only in memory: a restart cancels them, which is
// the safe way to fail. Only their hashes are kept.

const maxCodes = 16

type pendingCode struct {
	expires time.Time
	by      string // the device that asked for it
}

func (v *vault) newCode(by string, now time.Time, ttl time.Duration) (Enrolment, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for h, c := range v.codes {
		if !now.Before(c.expires) {
			delete(v.codes, h)
		}
	}
	if len(v.codes) >= maxCodes {
		return Enrolment{}, errTooMany
	}
	code := newEnrolmentCode()
	exp := now.Add(ttl)
	v.codes[sha256.Sum256([]byte(code))] = pendingCode{expires: exp, by: by}
	return Enrolment{Code: code, Expires: exp.UTC()}, nil
}

// useCode spends a code, returning the device that asked for it, and
// false if it was not outstanding or has expired. Either way it cannot be
// used again.
func (v *vault) useCode(code string, now time.Time) (by string, ok bool) {
	h := sha256.Sum256([]byte(normaliseCode(code)))
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.codes[h]
	delete(v.codes, h)
	if !ok || !now.Before(c.expires) {
		return "", false
	}
	// The device that asked may have been removed since.
	if v.findDevice(c.by) < 0 {
		return "", false
	}
	return c.by, true
}

func (v *vault) close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.log.close()
}
