package svimport

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Zip archives, as 1Password and Proton Pass export them.

// zipMember returns the contents of the archive's first member for which
// match is true (members are tried in archive order), and every member's
// name.
func zipMember(data []byte, match func(name string) bool) ([]byte, []string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: not a zip archive: %v", ErrFormat, err)
	}
	var names []string
	var found *zip.File
	for _, f := range zr.File {
		names = append(names, f.Name)
		if found == nil && !f.FileInfo().IsDir() && match(f.Name) {
			found = f
		}
	}
	if found == nil {
		return nil, names, fmt.Errorf("%w: the archive holds no export data", ErrFormat)
	}
	rc, err := found.Open()
	if err != nil {
		return nil, names, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxInput+1))
	if err != nil {
		return nil, names, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if len(b) > maxInput {
		return nil, names, fmt.Errorf("%w: %s is larger than %d MiB", ErrUnsupported, found.Name, maxInput>>20)
	}
	return b, names, nil
}

// filesUnder counts the files in an archive under a folder name, at any
// depth ("files/" matches "files/x" and "Proton Pass/files/x").
func filesUnder(names []string, folder string) int {
	n := 0
	for _, name := range names {
		if !strings.HasSuffix(name, "/") && (strings.HasPrefix(name, folder) || strings.Contains(name, "/"+folder)) {
			n++
		}
	}
	return n
}
