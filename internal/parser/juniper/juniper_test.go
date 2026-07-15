package juniper

import (
	"testing"

	"network-compiler/internal/ir"
)

func TestParseJunosSetFixture(t *testing.T) {
	dev, err := New().ParseFile("../../../testdata/corpus/juniper-junos/edge-sw1.set.conf")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "edge-sw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if dev.Vendor != "juniper" {
		t.Fatalf("vendor = %q", dev.Vendor)
	}
	if len(dev.VLANs) != 3 {
		t.Fatalf("vlans = %d, want 3", len(dev.VLANs))
	}
	if len(dev.Interfaces) != 4 {
		t.Fatalf("interfaces = %d, want 4", len(dev.Interfaces))
	}
	if len(dev.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(dev.Routes))
	}
	if len(dev.Services.NTPServers) != 1 || dev.Services.NTPServers[0].Value != "10.0.0.123" {
		t.Fatalf("ntp = %#v", dev.Services.NTPServers)
	}
	if len(dev.Services.SyslogHosts) != 1 || dev.Services.SyslogHosts[0].Value != "10.0.0.50" {
		t.Fatalf("syslog = %#v", dev.Services.SyslogHosts)
	}
	if len(dev.Services.SNMPCommunities) != 1 || dev.Services.SNMPCommunities[0].Value != "public" {
		t.Fatalf("snmp = %#v", dev.Services.SNMPCommunities)
	}

	access := findInterface(dev.Interfaces, "ge-0/0/1")
	if access == nil || access.Mode != "access" || access.AccessVLAN != 10 {
		t.Fatalf("access interface = %#v", access)
	}
	trunk := findInterface(dev.Interfaces, "ge-0/0/24")
	if trunk == nil || trunk.Mode != "trunk" || !containsInt(trunk.TrunkVLANs, 10) || !containsInt(trunk.TrunkVLANs, 20) || !containsInt(trunk.TrunkVLANs, 99) {
		t.Fatalf("trunk interface = %#v", trunk)
	}
	routed := findInterface(dev.Interfaces, "irb")
	if routed == nil || routed.Mode != "routed" || routed.IPv4 != "10.0.99.2/24" {
		t.Fatalf("routed interface = %#v", routed)
	}
	if trunk.Evidence.StartLine == 0 || trunk.Evidence.RawBlock == "" {
		t.Fatalf("missing evidence: %#v", trunk.Evidence)
	}
}

func findInterface(items []ir.Interface, name string) *ir.Interface {
	for i := range items {
		if items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

func containsInt(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
