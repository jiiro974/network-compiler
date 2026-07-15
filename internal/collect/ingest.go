package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"network-compiler/internal/diag"
)

func mergeCreds(user string, creds diag.CredRef) diag.CredRef {
	out := creds
	if strings.TrimSpace(out.Username) == "" {
		out.Username = user
	}
	return out
}

// ConfigPaths returns show-running-config.txt files from a collect output tree.
func ConfigPaths(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "show-running-config.txt")
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s: no show-running-config.txt files found", root)
	}
	sort.Strings(paths)
	return paths, nil
}
