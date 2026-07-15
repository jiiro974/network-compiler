package ioslike

import (
	"path/filepath"
	"testing"

	"network-compiler/internal/ir"
)

func TestParseIOSLikeCorpusFixtures(t *testing.T) {
	tests := []struct {
		name       string
		vendor     string
		file       string
		hostname   string
		interfaces int
		vlans      int
		routes     int
		ntp        string
		syslog     string
		snmp       string
		trunkName  string
		trunkVLAN  int
		routedName string
		routedIPv4 string
	}{
		{
			name:       "arista eos",
			vendor:     "arista-eos",
			file:       "../../../testdata/corpus/arista-eos/edge-sw1.cfg",
			hostname:   "edge-sw1",
			interfaces: 4,
			vlans:      3,
			routes:     2,
			ntp:        "10.0.0.123",
			syslog:     "10.0.0.50",
			snmp:       "public",
			trunkName:  "Ethernet24",
			trunkVLAN:  99,
			routedName: "Vlan99",
			routedIPv4: "10.0.99.2/24",
		},
		{
			name:       "cisco nxos",
			vendor:     "cisco-nxos",
			file:       "../../../testdata/corpus/cisco-nxos/edge-sw1.cfg",
			hostname:   "edge-sw1",
			interfaces: 4,
			vlans:      3,
			routes:     2,
			ntp:        "10.0.0.123",
			syslog:     "10.0.0.50",
			snmp:       "public",
			trunkName:  "Ethernet1/24",
			trunkVLAN:  99,
			routedName: "Vlan99",
			routedIPv4: "10.0.99.2/24",
		},
		{
			name:       "aruba cx",
			vendor:     "aruba-cx",
			file:       "../../../testdata/corpus/aruba-cx/edge-sw1.cfg",
			hostname:   "edge-sw1",
			interfaces: 4,
			vlans:      3,
			routes:     2,
			ntp:        "10.0.0.123",
			syslog:     "10.0.0.50",
			snmp:       "public",
			trunkName:  "1/1/24",
			trunkVLAN:  99,
			routedName: "vlan 99",
			routedIPv4: "10.0.99.2/24",
		},
		{
			name:       "fs fsos",
			vendor:     "fs-fsos",
			file:       "../../../testdata/corpus/fs-fsos/edge-sw1.cfg",
			hostname:   "edge-sw1",
			interfaces: 4,
			vlans:      3,
			routes:     2,
			ntp:        "10.0.0.123",
			syslog:     "",
			snmp:       "public",
			trunkName:  "eth-0-24",
			trunkVLAN:  99,
			routedName: "vlan 99",
			routedIPv4: "10.0.99.2/24",
		},
		{
			name:       "cisco iosxr",
			vendor:     "cisco-iosxr",
			file:       "../../../testdata/corpus/cisco-iosxr/edge-rtr1.cfg",
			hostname:   "edge-rtr1",
			interfaces: 5,
			vlans:      3,
			routes:     2,
			ntp:        "10.0.0.123",
			syslog:     "10.0.0.50",
			snmp:       "public",
			trunkName:  "GigabitEthernet0/0/0/1.99",
			trunkVLAN:  99,
			routedName: "GigabitEthernet0/0/0/1.99",
			routedIPv4: "10.0.99.2 255.255.255.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev, err := New(tt.vendor).ParseFile(filepath.Clean(tt.file))
			if err != nil {
				t.Fatal(err)
			}
			if dev.Hostname != tt.hostname {
				t.Fatalf("hostname = %q, want %q", dev.Hostname, tt.hostname)
			}
			if dev.Vendor != tt.vendor {
				t.Fatalf("vendor = %q, want %q", dev.Vendor, tt.vendor)
			}
			if len(dev.Interfaces) != tt.interfaces {
				t.Fatalf("interfaces = %d, want %d: %#v", len(dev.Interfaces), tt.interfaces, dev.Interfaces)
			}
			if len(dev.VLANs) != tt.vlans {
				t.Fatalf("vlans = %d, want %d: %#v", len(dev.VLANs), tt.vlans, dev.VLANs)
			}
			if len(dev.Routes) != tt.routes {
				t.Fatalf("routes = %d, want %d: %#v", len(dev.Routes), tt.routes, dev.Routes)
			}
			if firstServiceValue(dev.Services.NTPServers) != tt.ntp {
				t.Fatalf("ntp = %#v, want %q", dev.Services.NTPServers, tt.ntp)
			}
			if firstServiceValue(dev.Services.SyslogHosts) != tt.syslog {
				t.Fatalf("syslog = %#v, want %q", dev.Services.SyslogHosts, tt.syslog)
			}
			if firstServiceValue(dev.Services.SNMPCommunities) != tt.snmp {
				t.Fatalf("snmp = %#v, want %q", dev.Services.SNMPCommunities, tt.snmp)
			}
			trunk := findInterface(dev.Interfaces, tt.trunkName)
			if trunk == nil {
				t.Fatalf("missing trunk interface %q", tt.trunkName)
			}
			if tt.vendor == "cisco-iosxr" {
				if trunk.AccessVLAN != tt.trunkVLAN {
					t.Fatalf("%s access vlan = %d, want %d", tt.trunkName, trunk.AccessVLAN, tt.trunkVLAN)
				}
			} else if trunk.Mode != "trunk" || !containsInt(trunk.TrunkVLANs, tt.trunkVLAN) {
				t.Fatalf("unexpected trunk facts for %s: %#v", tt.trunkName, trunk)
			}
			routed := findInterface(dev.Interfaces, tt.routedName)
			if routed == nil {
				t.Fatalf("missing routed interface %q", tt.routedName)
			}
			if routed.Mode != "routed" || routed.IPv4 != tt.routedIPv4 {
				t.Fatalf("unexpected routed facts for %s: %#v", tt.routedName, routed)
			}
			if dev.Evidence.StartLine == 0 || dev.Evidence.RawBlock == "" {
				t.Fatalf("missing device evidence: %#v", dev.Evidence)
			}
			if dev.Interfaces[0].Evidence.StartLine == 0 || dev.Interfaces[0].Evidence.RawBlock == "" {
				t.Fatalf("missing interface evidence: %#v", dev.Interfaces[0].Evidence)
			}
		})
	}
}

func firstServiceValue(items []ir.ServiceTarget) string {
	if len(items) == 0 {
		return ""
	}
	return items[0].Value
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
