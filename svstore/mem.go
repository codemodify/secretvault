package svstore

import (
	"sort"
	"strings"
	"sync"
)

// Mem is a Backend in memory, for tests and for the session collection
// (secrets that must never touch a disk).
type Mem struct {
	mu    sync.Mutex
	files map[string][]byte
}

// NewMem returns an empty in-memory backend.
func NewMem() *Mem { return &Mem{files: map[string][]byte{}} }

func (m *Mem) Create(name string, data []byte) error {
	if err := CheckName(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[name]; ok {
		return ErrExist
	}
	m.files[name] = append([]byte{}, data...)
	return nil
}

func (m *Mem) Write(name string, data []byte) error {
	if err := CheckName(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[name] = append([]byte{}, data...)
	return nil
}

func (m *Mem) Read(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[name]
	if !ok {
		return nil, ErrNotExist
	}
	return append([]byte{}, b...), nil
}

func (m *Mem) List(dir string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := dir
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var names []string
	for n := range m.files {
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (m *Mem) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, name)
	return nil
}
