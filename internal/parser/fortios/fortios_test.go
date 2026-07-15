package fortios

import (
	"testing"

	"network-compiler/internal/ir"
)

func TestParseFortiOSFixture(t *testing.T) {
	dev, err := New().ParseFile("../../../testdata/corpus/fortinet-fortigate/edge-fw1.conf")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "edge-fw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.Interfaces) != 4 {
		t.Fatalf("interfaces = %d: %#v", len(dev.Interfaces), dev.Interfaces)
	}
	if len(dev.VLANs) != 2 {
		t.Fatalf("vlans = %d: %#v", len(dev.VLANs), dev.VLANs)
	}
	if len(dev.Routes) != 2 || dev.Routes[0].Destination != "0.0.0.0/0" || dev.Routes[0].NextHop != "10.0.99.1" {
		t.Fatalf("routes = %#v", dev.Routes)
	}
	if len(dev.Services.NTPServers) != 1 || dev.Services.NTPServers[0].Value != "10.0.0.123" {
		t.Fatalf("ntp = %#v", dev.Services.NTPServers)
	}
	if len(dev.Services.SyslogHosts) != 0 {
		t.Fatalf("syslog = %#v", dev.Services.SyslogHosts)
	}
	if len(dev.Services.SNMPCommunities) != 1 || dev.Services.SNMPCommunities[0].Value != "public" {
		t.Fatalf("snmp = %#v", dev.Services.SNMPCommunities)
	}
	if len(dev.SNMP.Hosts) != 1 || dev.SNMP.Hosts[0].Host != "10.0.0.50" {
		t.Fatalf("snmp hosts = %#v", dev.SNMP.Hosts)
	}
	if got := findInterface(dev.Interfaces, "vlan10-users"); got == nil || got.AccessVLAN != 10 || got.IPv4 != "10.0.10.1/24" {
		t.Fatalf("vlan10-users = %#v", got)
	}
	if got := findInterface(dev.Interfaces, "port48"); got == nil || !got.Shutdown {
		t.Fatalf("port48 = %#v", got)
	}
	if len(dev.Zones) != 2 || dev.Zones[0].Name != "internal" || len(dev.Zones[0].Interfaces) != 2 {
		t.Fatalf("zones = %#v", dev.Zones)
	}
	if dev.Zones[0].Evidence.RawBlock == "" || dev.Zones[0].Evidence.StartLine == 0 {
		t.Fatalf("zone evidence = %#v", dev.Zones[0].Evidence)
	}
	if len(dev.SecurityPolicies) != 2 {
		t.Fatalf("policies = %#v", dev.SecurityPolicies)
	}
	allow := dev.SecurityPolicies[0]
	if allow.Name != "users-to-lab" || allow.FromZone != "internal" || allow.ToZone != "wan" || allow.Action != "accept" || allow.Service != "HTTPS" || allow.Evidence.RawBlock == "" {
		t.Fatalf("allow policy = %#v", allow)
	}
	deny := dev.SecurityPolicies[1]
	if deny.Name != "ssh-deny" || deny.FromZone != "internal" || deny.ToZone != "wan" || deny.Action != "deny" || deny.Service != "SSH" || deny.Evidence.RawBlock == "" {
		t.Fatalf("deny policy = %#v", deny)
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
