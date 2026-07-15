package query

import (
	"net"
	"testing"

	"network-compiler/internal/ir"
)

func TestFindRouteDstLongestPrefix(t *testing.T) {
	dev := ir.Device{
		Hostname: "r1",
		Routes: []ir.Route{
			{Destination: "192.168.0.0 255.255.0.0", NextHop: "10.0.0.1", Evidence: ev("r1.cfg", 1, "ip route 192.168.0.0 255.255.0.0 10.0.0.1")},
			{Destination: "192.168.50.0 255.255.255.0", NextHop: "10.0.0.2", Evidence: ev("r1.cfg", 2, "ip route 192.168.50.0 255.255.255.0 10.0.0.2")},
		},
	}
	results := findRouteDst(dev, "192.168.50.10")
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Object.(ir.Route).NextHop != "10.0.0.2" {
		t.Fatalf("next hop = %q, want 10.0.0.2", results[0].Object.(ir.Route).NextHop)
	}
}

func TestParseRoutePrefixFormats(t *testing.T) {
	tests := []struct {
		dest string
		ip   string
		bits int
	}{
		{dest: "192.168.50.0 255.255.255.0", ip: "192.168.50.0", bits: 24},
		{dest: "10.0.0.0/8", ip: "10.0.0.0", bits: 8},
	}
	for _, tt := range tests {
		prefix, ok := parseRoutePrefix(tt.dest)
		if !ok {
			t.Fatalf("parseRoutePrefix(%q) failed", tt.dest)
		}
		if prefix.IP.String() != tt.ip {
			t.Fatalf("ip = %q, want %q", prefix.IP.String(), tt.ip)
		}
		ones, _ := prefix.Mask.Size()
		if ones != tt.bits {
			t.Fatalf("bits = %d, want %d", ones, tt.bits)
		}
	}
}

func TestParseQueryPrefixDefaults(t *testing.T) {
	prefix, ok := parseQueryPrefix("192.168.50.0")
	if !ok {
		t.Fatal("parseQueryPrefix failed")
	}
	ones, _ := prefix.Mask.Size()
	if ones != 24 {
		t.Fatalf("bits = %d, want 24", ones)
	}
	ip := net.ParseIP("192.168.50.100")
	if !prefix.Contains(ip) {
		t.Fatal("expected /24 to contain host address")
	}
}

func TestRunZonesAndPolicies(t *testing.T) {
	dev := ir.Device{
		Hostname: "fw1",
		Zones: []ir.Zone{
			{Name: "trust", Evidence: ev("fw1.conf", 1, "zone trust")},
		},
		SecurityPolicies: []ir.SecurityPolicy{
			{Name: "allow-web", Action: "allow", Evidence: ev("fw1.conf", 2, "policy allow-web")},
		},
	}
	zones, err := Run([]ir.Device{dev}, "zones")
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].Type != "zone" {
		t.Fatalf("zones = %#v", zones)
	}
	policies, err := Run([]ir.Device{dev}, "politiques")
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || policies[0].Type != "policy" {
		t.Fatalf("policies = %#v", policies)
	}
}
