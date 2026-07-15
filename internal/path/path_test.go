package path

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"network-compiler/internal/ir"
)

func TestTraceVerdicts(t *testing.T) {
	tests := []struct {
		name      string
		devices   []ir.Device
		flow      Flow
		verdict   Verdict
		hops      int
		reasonIn  string
		policy    bool
		acl       bool
		nat       bool
		egressDev string
	}{
		{
			name:      "multi hop delivered with dotted masks",
			devices:   deliveredDevices(),
			flow:      Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443},
			verdict:   VerdictDelivered,
			hops:      2,
			reasonIn:  "interface vlan50",
			egressDev: "core-rtr1",
		},
		{
			name:     "no route",
			devices:  []ir.Device{router("edge-sw1", "10.0.10.1/24", nil)},
			flow:     Flow{Src: "10.0.10.55", Dst: "198.51.100.20", Proto: "tcp", DPort: 443},
			verdict:  VerdictNoRoute,
			hops:     1,
			reasonIn: "device edge-sw1",
		},
		{
			name:    "dropped acl",
			devices: []ir.Device{aclRouter()},
			flow:    Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443},
			verdict: VerdictDroppedACL,
			hops:    1,
			acl:     true,
		},
		{
			name:    "dropped firewall policy",
			devices: []ir.Device{firewall("deny")},
			flow:    Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 22},
			verdict: VerdictDroppedPolicy,
			hops:    1,
			policy:  true,
		},
		{
			name:    "firewall delivered with nat traced",
			devices: []ir.Device{firewall("allow")},
			flow:    Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443},
			verdict: VerdictDelivered,
			hops:    1,
			policy:  true,
			nat:     true,
		},
		{
			name:     "loop",
			devices:  loopDevices(),
			flow:     Flow{Src: "10.0.10.55", Dst: "203.0.113.20", Proto: "udp", DPort: 53},
			verdict:  VerdictLoop,
			hops:     2,
			reasonIn: "device edge-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Trace(tt.devices, tt.flow)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tt.verdict {
				t.Fatalf("verdict = %s, want %s; path=%#v", got.Verdict, tt.verdict, got)
			}
			if len(got.Hops) != tt.hops {
				t.Fatalf("hops = %d, want %d; path=%#v", len(got.Hops), tt.hops, got)
			}
			if tt.reasonIn != "" && (got.Reason == nil || !strings.Contains(got.Reason.RawBlock, tt.reasonIn)) {
				t.Fatalf("reason = %#v, want raw containing %q", got.Reason, tt.reasonIn)
			}
			last := got.Hops[len(got.Hops)-1]
			if tt.policy && last.PolicyMatch == nil {
				t.Fatalf("missing policy match: %#v", last)
			}
			if tt.acl && last.ACLMatch == nil {
				t.Fatalf("missing ACL match: %#v", last)
			}
			if tt.nat && last.NATApplied == nil {
				t.Fatalf("missing NAT trace: %#v", last)
			}
			if tt.egressDev != "" && last.Device != tt.egressDev {
				t.Fatalf("last device = %q, want %q", last.Device, tt.egressDev)
			}
		})
	}
}

func TestTraceRejectsInvalidFlow(t *testing.T) {
	if _, err := Trace(deliveredDevices(), Flow{Src: "bad", Dst: "192.168.50.20", Proto: "tcp"}); err == nil {
		t.Fatal("expected invalid src error")
	}
	if _, err := Trace(deliveredDevices(), Flow{Src: "10.0.10.55", Dst: "bad", Proto: "tcp"}); err == nil {
		t.Fatal("expected invalid dst error")
	}
	if _, err := Trace(deliveredDevices(), Flow{Src: "10.0.10.55", Dst: "192.168.50.20"}); err == nil {
		t.Fatal("expected missing proto error")
	}
}

func TestTraceNoSourceSubnet(t *testing.T) {
	got, err := Trace(deliveredDevices(), Flow{Src: "172.16.1.10", Dst: "192.168.50.20", Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictNoRoute || len(got.Hops) != 0 {
		t.Fatalf("path = %#v", got)
	}
}

func TestFlowOmitsZeroDPort(t *testing.T) {
	data, err := json.Marshal(Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "dport") {
		t.Fatalf("zero dport should be omitted: %s", data)
	}
}

func TestTracePolicyDefaultDenyWhenNoPolicyMatches(t *testing.T) {
	dev := firewall("allow")
	dev.SecurityPolicies[0].Service = "tcp-22"
	got, err := Trace([]ir.Device{dev}, Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictDroppedPolicy || got.Reason == nil || !strings.Contains(got.Reason.RawBlock, "device edge-fw1") {
		t.Fatalf("path = %#v", got)
	}
}

func TestRouteSelectionAndParsingHelpers(t *testing.T) {
	dev := router("edge", "10.0.10.1/24", []ir.Route{
		{Destination: "192.168.0.0/16", NextHop: "10.0.10.254", AdministrativeDistance: "1"},
		{Destination: "192.168.50.0/24", NextHop: "10.0.10.253", AdministrativeDistance: "200"},
		{Destination: "192.168.50.0/24", NextHop: "10.0.10.252", AdministrativeDistance: "20"},
	})
	dst := mustAddr(t, "192.168.50.20")
	choice, ok := longestPrefixRoute(dev, dst)
	if !ok {
		t.Fatal("no route selected")
	}
	if choice.route.NextHop != "10.0.10.252" {
		t.Fatalf("selected route = %#v", choice.route)
	}
	if administrativeDistance("not-a-number") != 0 {
		t.Fatal("invalid administrative distance should be zero")
	}
	if _, _, ok := parseInterfaceIPv4(""); ok {
		t.Fatal("empty interface address parsed")
	}
	if _, _, ok := parseInterfaceIPv4("10.0.0.1 255.0.255.0"); ok {
		t.Fatal("non-contiguous mask parsed")
	}
	if _, _, ok := parseInterfaceIPv4("not-ip"); ok {
		t.Fatal("invalid interface address parsed")
	}
}

func TestNextHopAndMatchHelpers(t *testing.T) {
	refs := indexInterfaces(deliveredDevices())
	if _, ok := resolveNextHop(refs, 0, "10.0.99.2"); !ok {
		t.Fatal("exact next hop did not resolve")
	}
	if _, ok := resolveNextHop(refs, 0, "10.0.99.3"); !ok {
		t.Fatal("same-subnet next hop did not resolve")
	}
	if _, ok := resolveNextHop(refs, 0, "not-ip"); ok {
		t.Fatal("invalid next hop resolved")
	}
	if _, ok := containingInterface(refs, mustAddr(t, "172.16.0.1")); ok {
		t.Fatal("unexpected containing interface")
	}
	if egressInterface(deliveredDevices()[0], ir.Route{NextHop: "not-ip"}) != "" {
		t.Fatal("invalid next-hop should not choose egress interface")
	}
	if serviceMatches("http", Flow{Proto: "tcp", DPort: 443}) {
		t.Fatal("http matched tcp/443")
	}
	if !serviceMatches("service-https", Flow{Proto: "tcp", DPort: 443}) {
		t.Fatal("service-https did not match tcp/443")
	}
	if aclEntryMatches(ir.ACLEntry{Protocol: "udp"}, Flow{Proto: "tcp", DPort: 53}) {
		t.Fatal("udp ACL matched tcp flow")
	}
	if !aclEntryMatches(ir.ACLEntry{Protocol: "ip", Raw: "permit ip any any"}, Flow{Proto: "tcp", DPort: 443}) {
		t.Fatal("ip ACL did not match")
	}
}

func TestTraceNoRouteKeepsEmptyHopsArray(t *testing.T) {
	got, err := Trace(deliveredDevices(), Flow{Src: "172.16.1.10", Dst: "192.168.50.20", Proto: "tcp", DPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got.Hops == nil {
		t.Fatal("hops must be an empty array, not null")
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"hops":null`) {
		t.Fatalf("hops serialized as null: %s", data)
	}
}

func TestGoldenDeliveredJSON(t *testing.T) {
	got, err := Trace(deliveredDevices(), Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	golden, err := os.ReadFile(filepath.Join("testdata", "delivered_path.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(golden) {
		t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", data, golden)
	}
}

func deliveredDevices() []ir.Device {
	return []ir.Device{
		{
			Hostname: "edge-sw1",
			Vendor:   "cisco-ios",
			Evidence: ev("edge.cfg", 1, "device edge-sw1"),
			Interfaces: []ir.Interface{
				{Name: "Vlan10", IPv4: "10.0.10.1 255.255.255.0", Evidence: ev("edge.cfg", 10, "interface vlan10")},
				{Name: "Gi1/0/24", IPv4: "10.0.99.1 255.255.255.252", Evidence: ev("edge.cfg", 20, "interface transit")},
			},
			Routes: []ir.Route{
				{Destination: "0.0.0.0 0.0.0.0", NextHop: "10.0.99.2", Evidence: ev("edge.cfg", 30, "ip route 0.0.0.0 0.0.0.0 10.0.99.2")},
			},
		},
		{
			Hostname: "core-rtr1",
			Vendor:   "juniper",
			Evidence: ev("core.set", 1, "device core-rtr1"),
			Interfaces: []ir.Interface{
				{Name: "ge-0/0/0", IPv4: "10.0.99.2/30", Evidence: ev("core.set", 10, "interface transit")},
				{Name: "ge-0/0/3", IPv4: "192.168.50.1/24", Evidence: ev("core.set", 20, "interface vlan50")},
			},
			Routes: []ir.Route{
				{Destination: "192.168.50.0/24", NextHop: "192.168.50.20", Interface: "ge-0/0/3", AdministrativeDistance: "5", Evidence: ev("core.set", 30, "route lab")},
			},
		},
	}
}

func router(name, lan string, routes []ir.Route) ir.Device {
	return ir.Device{
		Hostname: name,
		Vendor:   "cisco-ios",
		Evidence: ev(name+".cfg", 1, "device "+name),
		Interfaces: []ir.Interface{
			{Name: "Vlan10", IPv4: lan, Evidence: ev(name+".cfg", 10, "interface vlan10")},
		},
		Routes: routes,
	}
}

func aclRouter() ir.Device {
	dev := router("edge-acl", "10.0.10.1/24", []ir.Route{
		{Destination: "0.0.0.0/0", NextHop: "10.0.10.254", Evidence: ev("acl.cfg", 20, "default route")},
	})
	dev.ACLs = []ir.ACL{{
		Name: "OUT",
		Entries: []ir.ACLEntry{
			{Action: "deny", Protocol: "tcp", Match: "eq 443", Raw: "deny tcp any any eq 443", Evidence: ev("acl.cfg", 30, "deny tcp any any eq 443")},
		},
		Evidence: ev("acl.cfg", 29, "ip access-list extended OUT"),
	}}
	return dev
}

func firewall(action string) ir.Device {
	return ir.Device{
		Hostname: "edge-fw1",
		Vendor:   "pan-os",
		Evidence: ev("fw.set", 1, "device edge-fw1"),
		Interfaces: []ir.Interface{
			{Name: "ethernet1/2", IPv4: "10.0.10.1/24", Evidence: ev("fw.set", 10, "interface trust")},
			{Name: "ethernet1/1", IPv4: "192.168.50.1/24", Evidence: ev("fw.set", 20, "interface dmz")},
		},
		Zones: []ir.Zone{
			{Name: "trust", Interfaces: []string{"ethernet1/2"}, Evidence: ev("fw.set", 30, "zone trust")},
			{Name: "dmz", Interfaces: []string{"ethernet1/1"}, Evidence: ev("fw.set", 31, "zone dmz")},
		},
		SecurityPolicies: []ir.SecurityPolicy{
			{Name: "users-to-lab", FromZone: "trust", ToZone: "dmz", Service: serviceForAction(action), Action: action, Evidence: ev("fw.set", 40, "policy "+action)},
		},
		NATRules: []ir.NATRule{
			{Name: "srcnat-users", FromZone: "trust", ToZone: "dmz", Kind: "source", Translated: "10.0.99.10", Evidence: ev("fw.set", 50, "nat source")},
		},
	}
}

func serviceForAction(action string) string {
	if action == "deny" {
		return "tcp-22"
	}
	return "tcp-443"
}

func loopDevices() []ir.Device {
	return []ir.Device{
		{
			Hostname: "edge-a",
			Vendor:   "cisco-ios",
			Evidence: ev("a.cfg", 1, "device edge-a"),
			Interfaces: []ir.Interface{
				{Name: "lan", IPv4: "10.0.10.1/24", Evidence: ev("a.cfg", 10, "interface lan")},
				{Name: "wan", IPv4: "10.0.99.1/30", Evidence: ev("a.cfg", 20, "interface wan")},
			},
			Routes: []ir.Route{{Destination: "203.0.113.0/24", NextHop: "10.0.99.2", Evidence: ev("a.cfg", 30, "route to b")}},
		},
		{
			Hostname: "edge-b",
			Vendor:   "cisco-ios",
			Evidence: ev("b.cfg", 1, "device edge-b"),
			Interfaces: []ir.Interface{
				{Name: "wan", IPv4: "10.0.99.2/30", Evidence: ev("b.cfg", 10, "interface wan")},
			},
			Routes: []ir.Route{{Destination: "203.0.113.0/24", NextHop: "10.0.99.1", Evidence: ev("b.cfg", 20, "route to a")}},
		},
	}
}

func ev(file string, line int, raw string) ir.Evidence {
	return ir.Evidence{File: file, StartLine: line, EndLine: line, RawBlock: raw, Parser: "test"}
}

func mustAddr(t *testing.T, raw string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
