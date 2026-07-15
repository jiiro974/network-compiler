package setform

import (
	"os"
	"path/filepath"
	"testing"

	"network-compiler/internal/ir"
)

func TestParseVyOSFixture(t *testing.T) {
	dev, err := NewVendor("vyos").ParseFile("../../../testdata/corpus/vyos/edge-rtr1.conf")
	if err != nil {
		t.Fatal(err)
	}
	assertCore(t, dev, "edge-rtr1", "vyos", 7, 3, 2, true)
	if got := findInterface(dev.Interfaces, "eth24.99"); got == nil || got.IPv4 != "10.0.99.2/24" || got.Mode != "routed" {
		t.Fatalf("eth24.99 = %#v", got)
	}
	if got := findInterface(dev.Interfaces, "eth48"); got == nil || !got.Shutdown {
		t.Fatalf("eth48 = %#v", got)
	}
}

func TestParseEdgeOSFixture(t *testing.T) {
	dev, err := NewVendor("ubiquiti-edgeos").ParseFile("../../../testdata/corpus/ubiquiti-edgeos/edge-rtr1.conf")
	if err != nil {
		t.Fatal(err)
	}
	assertCore(t, dev, "edge-rtr1", "ubiquiti-edgeos", 6, 3, 2, true)
	if got := findInterface(dev.Interfaces, "eth0.99"); got == nil || got.Description != "MGMT" || got.IPv4 != "10.0.99.2/24" {
		t.Fatalf("eth0.99 = %#v", got)
	}
}

func TestParsePANOSFixture(t *testing.T) {
	dev, err := NewVendor("paloalto-panos").ParseFile("../../../testdata/corpus/paloalto-panos/edge-fw1.set.conf")
	if err != nil {
		t.Fatal(err)
	}
	assertCore(t, dev, "edge-fw1", "paloalto-panos", 5, 3, 2, true)
	if got := findInterface(dev.Interfaces, "ethernet1/1.99"); got == nil || got.AccessVLAN != 99 || got.IPv4 != "10.0.99.2/24" {
		t.Fatalf("ethernet1/1.99 = %#v", got)
	}
	if got := findInterface(dev.Interfaces, "ethernet1/2"); got == nil || got.Description != "user-access" || got.IPv4 != "10.0.10.254/24" {
		t.Fatalf("ethernet1/2 = %#v", got)
	}
	if dev.Routes[0].VRF != "default" || dev.Routes[0].NextHop != "10.0.99.1" {
		t.Fatalf("route = %#v", dev.Routes[0])
	}
	if len(dev.Zones) != 2 || dev.Zones[0].Name != "trust" || len(dev.Zones[0].Interfaces) != 3 {
		t.Fatalf("zones = %#v", dev.Zones)
	}
}

func TestParsePANOSFirewallObjectsWithEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.set")
	data := []byte(`set deviceconfig system hostname fw1
set network interface ethernet ethernet1/1 layer3 ip 10.0.10.1/24
set network interface ethernet ethernet1/2 layer3 ip 192.168.50.1/24
set zone trust network layer3 ethernet1/1
set zone dmz network layer3 ethernet1/2
set rulebase security rules users-to-lab from trust
set rulebase security rules users-to-lab to dmz
set rulebase security rules users-to-lab application ssl
set rulebase security rules users-to-lab service tcp-443
set rulebase security rules users-to-lab action allow
set rulebase nat rules srcnat-users from trust
set rulebase nat rules srcnat-users to dmz
set rulebase nat rules srcnat-users source-translation dynamic-ip-and-port translated-address 203.0.113.10
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	dev, err := NewVendor("paloalto-panos").ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(dev.Zones) != 2 || dev.Zones[0].Evidence.RawBlock == "" {
		t.Fatalf("zones = %#v", dev.Zones)
	}
	if len(dev.SecurityPolicies) != 1 {
		t.Fatalf("policies = %#v", dev.SecurityPolicies)
	}
	policy := dev.SecurityPolicies[0]
	if policy.Name != "users-to-lab" || policy.FromZone != "trust" || policy.ToZone != "dmz" || policy.Application != "ssl" || policy.Service != "tcp-443" || policy.Action != "allow" || policy.Evidence.RawBlock == "" {
		t.Fatalf("policy = %#v", policy)
	}
	if len(dev.NATRules) != 1 {
		t.Fatalf("nat rules = %#v", dev.NATRules)
	}
	nat := dev.NATRules[0]
	if nat.Name != "srcnat-users" || nat.FromZone != "trust" || nat.ToZone != "dmz" || nat.Kind != "source" || nat.Translated != "203.0.113.10" || nat.Evidence.RawBlock == "" {
		t.Fatalf("nat = %#v", nat)
	}
}

func assertCore(t *testing.T, dev ir.Device, hostname, vendor string, wantIfaces, wantVLANs, wantRoutes int, wantServices bool) {
	t.Helper()
	if dev.Hostname != hostname {
		t.Fatalf("hostname = %q, want %q", dev.Hostname, hostname)
	}
	if dev.Vendor != vendor {
		t.Fatalf("vendor = %q, want %q", dev.Vendor, vendor)
	}
	if len(dev.Interfaces) != wantIfaces {
		t.Fatalf("interfaces = %d, want %d: %#v", len(dev.Interfaces), wantIfaces, dev.Interfaces)
	}
	if len(dev.VLANs) != wantVLANs {
		t.Fatalf("vlans = %d, want %d: %#v", len(dev.VLANs), wantVLANs, dev.VLANs)
	}
	if len(dev.Routes) != wantRoutes {
		t.Fatalf("routes = %d, want %d: %#v", len(dev.Routes), wantRoutes, dev.Routes)
	}
	if wantServices {
		if len(dev.Services.NTPServers) != 1 || dev.Services.NTPServers[0].Value != "10.0.0.123" {
			t.Fatalf("ntp = %#v", dev.Services.NTPServers)
		}
		if len(dev.Services.SyslogHosts) != 1 || dev.Services.SyslogHosts[0].Value != "10.0.0.50" {
			t.Fatalf("syslog = %#v", dev.Services.SyslogHosts)
		}
		if len(dev.Services.SNMPCommunities) != 1 || dev.Services.SNMPCommunities[0].Value != "public" {
			t.Fatalf("snmp = %#v", dev.Services.SNMPCommunities)
		}
	}
	if len(dev.Interfaces) > 0 && (dev.Interfaces[0].Evidence.StartLine == 0 || dev.Interfaces[0].Evidence.RawBlock == "") {
		t.Fatalf("missing interface evidence: %#v", dev.Interfaces[0].Evidence)
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
