package cisco

import "testing"

func TestParseRouteWithOutgoingInterfaceAndDistance(t *testing.T) {
	route, ok := parseRoute("inline.cfg", line{
		num:  7,
		text: "ip route 203.0.113.0 255.255.255.0 GigabitEthernet1/0/48 198.51.100.1 20",
	})
	if !ok {
		t.Fatal("route was not parsed")
	}
	if route.Destination != "203.0.113.0 255.255.255.0" {
		t.Fatalf("destination = %q", route.Destination)
	}
	if route.Interface != "GigabitEthernet1/0/48" || route.NextHop != "198.51.100.1" || route.AdministrativeDistance != "20" {
		t.Fatalf("route = %#v", route)
	}
	if route.Evidence.File != "inline.cfg" || route.Evidence.StartLine != 7 || route.Evidence.EndLine != 7 || route.Evidence.RawBlock == "" {
		t.Fatalf("evidence = %#v", route.Evidence)
	}
}

func TestParseAccessListsStandardAndExtended(t *testing.T) {
	parsed := appendACL("inline.cfg", nil, line{num: 11, text: "access-list 10 permit 192.0.2.0 0.0.0.255"})
	parsed = appendACL("inline.cfg", parsed, line{num: 12, text: "access-list 101 permit tcp any host 198.51.100.10 eq 443"})

	if len(parsed) != 2 {
		t.Fatalf("acls len = %d", len(parsed))
	}
	if parsed[0].Name != "10" || parsed[0].Entries[0].Action != "permit" || parsed[0].Entries[0].Match != "192.0.2.0 0.0.0.255" {
		t.Fatalf("standard acl = %#v", parsed[0])
	}
	if parsed[1].Name != "101" || parsed[1].Entries[0].Protocol != "tcp" || parsed[1].Entries[0].Match != "any host 198.51.100.10 eq 443" {
		t.Fatalf("extended acl = %#v", parsed[1])
	}
	if parsed[1].Evidence.File != "inline.cfg" || parsed[1].Evidence.RawBlock == "" {
		t.Fatalf("evidence = %#v", parsed[1].Evidence)
	}
}
