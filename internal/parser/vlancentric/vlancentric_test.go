package vlancentric

import (
	"path/filepath"
	"reflect"
	"testing"

	"network-compiler/internal/ir"
)

func TestProCurveLikeFixtures(t *testing.T) {
	tests := []struct {
		name       string
		parser     Parser
		path       string
		wantVLANs  int
		wantIface  int
		wantVendor string
	}{
		{
			name:       "aruba os switch",
			parser:     NewArubaOSSwitch(),
			path:       "aruba-os-switch/edge-sw1.cfg",
			wantVLANs:  3,
			wantIface:  4,
			wantVendor: string(FlavorArubaOSSwitch),
		},
		{
			name:       "hpe procurve",
			parser:     NewHPEProCurve(),
			path:       "hpe-procurve/edge-sw1.cfg",
			wantVLANs:  4,
			wantIface:  4,
			wantVendor: string(FlavorHPEProCurve),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev, err := tt.parser.ParseFile(corpusPath(tt.path))
			if err != nil {
				t.Fatal(err)
			}
			assertCommonSwitchFacts(t, dev, tt.wantVendor, tt.wantVLANs, tt.wantIface)
			assertInterface(t, dev, "1", "access", 10, nil, "user-access", false)
			assertInterface(t, dev, "24", "trunk", 0, []int{10, 20, 99}, "uplink-core", false)
			assertInterface(t, dev, "48", "unknown", 0, nil, "unused", true)
			assertInterface(t, dev, "Vlan99", "routed", 0, nil, "", false)
		})
	}
}

func TestExtremeEXOSFixture(t *testing.T) {
	dev, err := NewExtremeEXOS().ParseFile(corpusPath("extreme-exos/edge-sw1.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	assertCommonSwitchFacts(t, dev, string(FlavorExtremeEXOS), 3, 4)
	assertInterface(t, dev, "1", "access", 10, nil, "user-access", false)
	assertInterface(t, dev, "24", "trunk", 0, []int{10, 20, 99}, "uplink-core", false)
	assertInterface(t, dev, "48", "unknown", 0, nil, "", true)
	assertInterface(t, dev, "Vlan99", "routed", 0, nil, "", false)
	if dev.Routes[0].Destination != "0.0.0.0/0" {
		t.Fatalf("default route destination = %q", dev.Routes[0].Destination)
	}
}

func assertCommonSwitchFacts(t *testing.T, dev ir.Device, vendor string, wantVLANs, wantIface int) {
	t.Helper()
	if dev.Vendor != vendor {
		t.Fatalf("vendor = %q, want %q", dev.Vendor, vendor)
	}
	if dev.Hostname != "edge-sw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.VLANs) != wantVLANs {
		t.Fatalf("vlans = %d, want %d: %#v", len(dev.VLANs), wantVLANs, dev.VLANs)
	}
	if len(dev.Interfaces) != wantIface {
		t.Fatalf("interfaces = %d, want %d: %#v", len(dev.Interfaces), wantIface, dev.Interfaces)
	}
	if len(dev.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(dev.Routes))
	}
	if len(dev.Services.NTPServers) != 1 || dev.Services.NTPServers[0].Value != "10.0.0.123" {
		t.Fatalf("ntp servers = %#v", dev.Services.NTPServers)
	}
	if len(dev.Services.SyslogHosts) != 1 || dev.Services.SyslogHosts[0].Value != "10.0.0.50" {
		t.Fatalf("syslog hosts = %#v", dev.Services.SyslogHosts)
	}
	if len(dev.Services.SNMPCommunities) != 1 || dev.Services.SNMPCommunities[0].Value != "public" {
		t.Fatalf("snmp communities = %#v", dev.Services.SNMPCommunities)
	}
}

func assertInterface(t *testing.T, dev ir.Device, name, mode string, accessVLAN int, trunkVLANs []int, description string, shutdown bool) {
	t.Helper()
	intf, ok := findInterface(dev, name)
	if !ok {
		t.Fatalf("missing interface %q in %#v", name, dev.Interfaces)
	}
	if intf.Mode != mode || intf.AccessVLAN != accessVLAN || intf.Description != description || intf.Shutdown != shutdown {
		t.Fatalf("interface %s = %#v", name, intf)
	}
	if !reflect.DeepEqual(intf.TrunkVLANs, trunkVLANs) {
		t.Fatalf("interface %s trunk vlans = %#v, want %#v", name, intf.TrunkVLANs, trunkVLANs)
	}
	if intf.Evidence.Parser == "" || intf.Evidence.RawBlock == "" {
		t.Fatalf("interface %s missing evidence: %#v", name, intf.Evidence)
	}
}

func findInterface(dev ir.Device, name string) (ir.Interface, bool) {
	for _, intf := range dev.Interfaces {
		if intf.Name == name {
			return intf, true
		}
	}
	return ir.Interface{}, false
}

func corpusPath(path string) string {
	return filepath.Join("..", "..", "..", "testdata", "corpus", path)
}
