package cisco

import "testing"

func TestParseCiscoFixture(t *testing.T) {
	dev, err := New().ParseFile("../../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "sw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.Interfaces) != 3 {
		t.Fatalf("interfaces = %d", len(dev.Interfaces))
	}
	trunk := dev.Interfaces[1]
	if trunk.Name != "GigabitEthernet1/0/24" || trunk.Mode != "trunk" {
		t.Fatalf("unexpected trunk: %#v", trunk)
	}
	if !containsInt(trunk.TrunkVLANs, 42) || !containsInt(trunk.TrunkVLANs, 90) {
		t.Fatalf("missing trunk vlans: %#v", trunk.TrunkVLANs)
	}
	if trunk.Evidence.StartLine == 0 || trunk.Evidence.RawBlock == "" {
		t.Fatalf("missing evidence: %#v", trunk.Evidence)
	}
	if len(dev.Routes) != 1 || dev.Routes[0].NextHop != "192.0.2.254" {
		t.Fatalf("unexpected routes: %#v", dev.Routes)
	}
	if len(dev.ACLs) != 2 {
		t.Fatalf("acls = %d, want 2", len(dev.ACLs))
	}
	if dev.ACLs[1].Name != "USERS-IN" || len(dev.ACLs[1].Entries) != 1 {
		t.Fatalf("unexpected named acl: %#v", dev.ACLs[1])
	}
	if len(dev.Services.NTPServers) != 1 || dev.Services.NTPServers[0].Value != "10.10.10.1" {
		t.Fatalf("unexpected ntp servers: %#v", dev.Services.NTPServers)
	}
	if len(dev.Services.SyslogHosts) != 1 || dev.Services.SyslogHosts[0].Value != "10.10.20.5" {
		t.Fatalf("unexpected syslog hosts: %#v", dev.Services.SyslogHosts)
	}
	if len(dev.Services.SNMPCommunities) != 1 || dev.Services.SNMPCommunities[0].Value != "public" {
		t.Fatalf("unexpected snmp communities: %#v", dev.Services.SNMPCommunities)
	}
}

func containsInt(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
