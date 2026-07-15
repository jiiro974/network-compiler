package sros

import (
	"testing"

	"network-compiler/internal/ir"
)

func TestParseSROSFixture(t *testing.T) {
	dev, err := New().ParseFile("../../../testdata/corpus/nokia-sros/edge-rtr1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "edge-rtr1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.Interfaces) != 4 {
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
	if len(dev.Services.SNMPCommunities) != 1 || dev.Services.SNMPCommunities[0].Value != "public" {
		t.Fatalf("snmp = %#v", dev.Services.SNMPCommunities)
	}
	if got := findInterface(dev.Interfaces, "1/1/24"); got == nil || got.Mode != "trunk" || got.Description != "uplink-core" {
		t.Fatalf("1/1/24 = %#v", got)
	}
	if got := findInterface(dev.Interfaces, "mgmt"); got == nil || got.IPv4 != "10.0.99.2/24" || got.AccessVLAN != 99 {
		t.Fatalf("mgmt = %#v", got)
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
