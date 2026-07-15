package vrp

import (
	"path/filepath"
	"reflect"
	"testing"

	"network-compiler/internal/ir"
)

func TestVRPFamilyFixtures(t *testing.T) {
	tests := []struct {
		name        string
		parser      Parser
		path        string
		vendor      string
		accessName  string
		trunkName   string
		unusedName  string
		routedName  string
		firstRoute  string
		secondRoute string
	}{
		{
			name:        "huawei vrp",
			parser:      NewHuaweiVRP(),
			path:        "huawei-vrp/edge-sw1.cfg",
			vendor:      string(FlavorHuaweiVRP),
			accessName:  "GigabitEthernet0/0/1",
			trunkName:   "GigabitEthernet0/0/24",
			unusedName:  "GigabitEthernet0/0/48",
			routedName:  "Vlanif99",
			firstRoute:  "0.0.0.0 0.0.0.0",
			secondRoute: "192.168.50.0 255.255.255.0",
		},
		{
			name:        "hpe comware",
			parser:      NewHPEComware(),
			path:        "hpe-comware/edge-sw1.cfg",
			vendor:      string(FlavorHPEComware),
			accessName:  "GigabitEthernet1/0/1",
			trunkName:   "GigabitEthernet1/0/24",
			unusedName:  "GigabitEthernet1/0/48",
			routedName:  "Vlan-interface99",
			firstRoute:  "0.0.0.0/0",
			secondRoute: "192.168.50.0/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev, err := tt.parser.ParseFile(corpusPath(tt.path))
			if err != nil {
				t.Fatal(err)
			}
			assertDeviceFacts(t, dev, tt.vendor)
			assertInterface(t, dev, tt.accessName, "access", 10, nil, "user-access", false)
			assertInterface(t, dev, tt.trunkName, "trunk", 0, []int{10, 20, 99}, "uplink-core", false)
			assertInterface(t, dev, tt.unusedName, "unknown", 0, nil, "unused", true)
			assertInterface(t, dev, tt.routedName, "routed", 0, nil, "management", false)
			if dev.Routes[0].Destination != tt.firstRoute || dev.Routes[1].Destination != tt.secondRoute {
				t.Fatalf("routes = %#v", dev.Routes)
			}
		})
	}
}

func assertDeviceFacts(t *testing.T, dev ir.Device, vendor string) {
	t.Helper()
	if dev.Vendor != vendor {
		t.Fatalf("vendor = %q, want %q", dev.Vendor, vendor)
	}
	if dev.Hostname != "edge-sw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.VLANs) != 3 {
		t.Fatalf("vlans = %d, want 3: %#v", len(dev.VLANs), dev.VLANs)
	}
	if len(dev.Interfaces) != 4 {
		t.Fatalf("interfaces = %d, want 4: %#v", len(dev.Interfaces), dev.Interfaces)
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
