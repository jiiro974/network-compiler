package cisco

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExternalCiscoCorpus(t *testing.T) {
	root := os.Getenv("NETC_CISCO_CORPUS")
	if root == "" {
		t.Skip("set NETC_CISCO_CORPUS to run the external Cisco corpus test")
	}

	files, err := filepath.Glob(filepath.Join(root, "*.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no .cfg files found in %s", root)
	}

	parser := New()
	var totalInterfaces, totalVLANs, totalRoutes, totalACLs int
	for _, file := range files {
		dev, err := parser.ParseFile(file)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		if dev.Hostname == "" {
			t.Fatalf("parse %s: missing hostname", file)
		}
		if len(dev.Interfaces) == 0 {
			t.Fatalf("parse %s: no interfaces extracted", file)
		}
		totalInterfaces += len(dev.Interfaces)
		totalVLANs += len(dev.VLANs)
		totalRoutes += len(dev.Routes)
		totalACLs += len(dev.ACLs)
	}

	t.Logf("parsed files=%d interfaces=%d vlans=%d routes=%d acls=%d", len(files), totalInterfaces, totalVLANs, totalRoutes, totalACLs)
}
