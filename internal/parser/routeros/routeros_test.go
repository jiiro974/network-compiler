package routeros

import (
	"testing"

	"network-compiler/internal/ir"
)

func TestParseRouterOSFixture(t *testing.T) {
	dev, err := New().ParseFile("../../../testdata/corpus/mikrotik-routeros/edge-rtr1.rsc")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "edge-rtr1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.Interfaces) != 7 {
		t.Fatalf("interfaces = %d: %#v", len(dev.Interfaces), dev.Interfaces)
	}
	if len(dev.VLANs) != 3 {
		t.Fatalf("vlans = %d: %#v", len(dev.VLANs), dev.VLANs)
	}
	if len(dev.Routes) != 2 || dev.Routes[0].NextHop != "10.0.99.1" {
		t.Fatalf("routes = %#v", dev.Routes)
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
	if got := findInterface(dev.Interfaces, "ether1"); got == nil || got.Mode != "access" || got.AccessVLAN != 10 || got.Description != "user-access" {
		t.Fatalf("ether1 = %#v", got)
	}
	if got := findInterface(dev.Interfaces, "ether24"); got == nil || got.Mode != "trunk" || !containsInt(got.TrunkVLANs, 99) {
		t.Fatalf("ether24 = %#v", got)
	}
	if got := findInterface(dev.Interfaces, "vlan99-mgmt"); got == nil || got.IPv4 != "10.0.99.2/24" {
		t.Fatalf("vlan99-mgmt = %#v", got)
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
