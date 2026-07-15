package discovery

import (
	"path/filepath"
	"testing"
)

func TestParseDirFindsLLDPCDPAndAddresses(t *testing.T) {
	got, err := ParseDir(filepath.Join("..", "..", "testdata", "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 4 {
		t.Fatalf("devices = %d, want 4", len(got.Devices))
	}
	if len(got.Neighbors) != 10 {
		t.Fatalf("neighbors = %d, want 10", len(got.Neighbors))
	}
	if len(got.Addresses) != 4 {
		t.Fatalf("addresses = %d, want 4", len(got.Addresses))
	}
	found := false
	for _, n := range got.Neighbors {
		if n.LocalDevice == "sw1" && n.LocalInterface == "Gi1/0/1" && n.RemoteDevice == "sw2" && n.RemoteInterface == "Gi0/1" && n.Protocol == "lldp" {
			found = true
			if n.Evidence.File == "" || n.Evidence.StartLine == 0 || n.Source.Command != "show lldp neighbors detail" || n.Status != "candidate" {
				t.Fatalf("bad evidence/source/status: %#v", n)
			}
		}
	}
	if !found {
		t.Fatalf("expected sw1 LLDP neighbor not found: %#v", got.Neighbors)
	}
}

func TestRunningConfigCreatesWeakDescriptionNeighborAndConfigIP(t *testing.T) {
	got, err := ParseDir(filepath.Join("..", "..", "testdata", "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	var foundDescription, foundIP bool
	for _, n := range got.Neighbors {
		if n.LocalDevice == "sw1" && n.LocalInterface == "Gi1/0/4" && n.RemoteDevice == "sw5" && n.RemoteInterface == "Gi0/4" {
			foundDescription = true
			if n.Protocol != "interface_description" || n.Confidence != 0.35 || n.Source.Command != "show running-config" {
				t.Fatalf("bad description neighbor: %#v", n)
			}
		}
	}
	for _, a := range got.Addresses {
		if a.Device == "sw1" && a.Interface == "Vlan10" && a.IP == "10.0.10.1" {
			foundIP = true
			if a.Kind != "config_ip" || a.Confidence != 0.7 || a.Source.Command != "show running-config" {
				t.Fatalf("bad config ip: %#v", a)
			}
		}
	}
	if !foundDescription {
		t.Fatal("description neighbor not found")
	}
	if !foundIP {
		t.Fatal("config ip not found")
	}
}

func TestMACAddressTableCreatesAddressNotCertainLink(t *testing.T) {
	got, err := ParseDir(filepath.Join("..", "..", "testdata", "discovery"))
	if err != nil {
		t.Fatal(err)
	}
	var macFacts int
	for _, a := range got.Addresses {
		if a.Kind == "mac_table" {
			macFacts++
			if a.Confidence >= 0.8 {
				t.Fatalf("mac confidence = %.2f, want medium", a.Confidence)
			}
		}
	}
	if macFacts != 2 {
		t.Fatalf("mac facts = %d, want 2", macFacts)
	}
}
