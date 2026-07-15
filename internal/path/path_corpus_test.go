package path

import (
	"path/filepath"
	"strings"
	"testing"

	"network-compiler/internal/ir"
	"network-compiler/internal/parser/fortios"
	"network-compiler/internal/parser/setform"
)

func TestTracePANOSCorpusDelivered(t *testing.T) {
	fw := mustParsePANOSCorpus(t)
	got, err := Trace([]ir.Device{fw, coreRouterForCorpus()}, Flow{
		Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictDelivered {
		t.Fatalf("verdict = %s, want delivered; path=%#v", got.Verdict, got)
	}
	if len(got.Hops) != 2 {
		t.Fatalf("hops = %d, want 2; path=%#v", len(got.Hops), got)
	}
	first := got.Hops[0]
	if first.Device != "edge-fw1" || first.IngressZone != "trust" || first.EgressZone != "mgmt" {
		t.Fatalf("first hop = %#v", first)
	}
	if first.PolicyMatch == nil || first.PolicyMatch.Name != "users-to-lab" {
		t.Fatalf("policy match = %#v", first.PolicyMatch)
	}
	if !evidenceFromCorpus(first.PolicyMatch.Evidence, "edge-fw1.set.conf", "action allow") {
		t.Fatalf("policy evidence = %#v", first.PolicyMatch.Evidence)
	}
	if got.Reason == nil || !strings.Contains(got.Reason.RawBlock, "192.168.50.1/24") {
		t.Fatalf("reason = %#v", got.Reason)
	}
}

func TestTracePANOSCorpusDroppedPolicy(t *testing.T) {
	fw := mustParsePANOSCorpus(t)
	got, err := Trace([]ir.Device{fw, coreRouterForCorpus()}, Flow{
		Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictDroppedPolicy {
		t.Fatalf("verdict = %s, want dropped_policy; path=%#v", got.Verdict, got)
	}
	if len(got.Hops) != 1 {
		t.Fatalf("hops = %d, want 1; path=%#v", len(got.Hops), got)
	}
	first := got.Hops[0]
	if first.PolicyMatch == nil || first.PolicyMatch.Name != "ssh-deny" {
		t.Fatalf("policy match = %#v", first.PolicyMatch)
	}
	if got.Reason == nil || !evidenceFromCorpus(*got.Reason, "edge-fw1.set.conf", "action deny") {
		t.Fatalf("reason = %#v", got.Reason)
	}
}

func TestTraceFortiGateCorpusDelivered(t *testing.T) {
	fw := mustParseFortiGateCorpus(t)
	got, err := Trace([]ir.Device{fw, coreRouterForCorpus()}, Flow{
		Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictDelivered {
		t.Fatalf("verdict = %s, want delivered; path=%#v", got.Verdict, got)
	}
	if len(got.Hops) != 2 {
		t.Fatalf("hops = %d, want 2; path=%#v", len(got.Hops), got)
	}
	first := got.Hops[0]
	if first.Device != "edge-fw1" || first.IngressZone != "internal" || first.EgressZone != "wan" {
		t.Fatalf("first hop = %#v", first)
	}
	if first.PolicyMatch == nil || first.PolicyMatch.Name != "users-to-lab" {
		t.Fatalf("policy match = %#v", first.PolicyMatch)
	}
	if !evidenceFromCorpus(first.PolicyMatch.Evidence, "edge-fw1.conf", "set action accept") {
		t.Fatalf("policy evidence = %#v", first.PolicyMatch.Evidence)
	}
	if got.Reason == nil || !strings.Contains(got.Reason.RawBlock, "192.168.50.1/24") {
		t.Fatalf("reason = %#v", got.Reason)
	}
}

func TestTraceFortiGateCorpusDroppedPolicy(t *testing.T) {
	fw := mustParseFortiGateCorpus(t)
	got, err := Trace([]ir.Device{fw, coreRouterForCorpus()}, Flow{
		Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 22,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != VerdictDroppedPolicy {
		t.Fatalf("verdict = %s, want dropped_policy; path=%#v", got.Verdict, got)
	}
	if len(got.Hops) != 1 {
		t.Fatalf("hops = %d, want 1; path=%#v", len(got.Hops), got)
	}
	first := got.Hops[0]
	if first.PolicyMatch == nil || first.PolicyMatch.Name != "ssh-deny" {
		t.Fatalf("policy match = %#v", first.PolicyMatch)
	}
	if got.Reason == nil || !evidenceFromCorpus(*got.Reason, "edge-fw1.conf", "set action deny") {
		t.Fatalf("reason = %#v", got.Reason)
	}
}

func mustParseFortiGateCorpus(t *testing.T) ir.Device {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "corpus", "fortinet-fortigate", "edge-fw1.conf")
	dev, err := fortios.New().ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "edge-fw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.SecurityPolicies) < 2 {
		t.Fatalf("policies = %#v", dev.SecurityPolicies)
	}
	return dev
}

func mustParsePANOSCorpus(t *testing.T) ir.Device {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "corpus", "paloalto-panos", "edge-fw1.set.conf")
	dev, err := setform.NewVendor("paloalto-panos").ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "edge-fw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.SecurityPolicies) < 2 {
		t.Fatalf("policies = %#v", dev.SecurityPolicies)
	}
	return dev
}

func coreRouterForCorpus() ir.Device {
	return ir.Device{
		Hostname: "core-rtr1",
		Vendor:   "juniper",
		Evidence: ir.Evidence{
			File: "core-rtr1.set", StartLine: 1, EndLine: 1,
			RawBlock: "set system host-name core-rtr1", Parser: "test",
		},
		Interfaces: []ir.Interface{
			{
				Name: "ge-0/0/0", IPv4: "10.0.99.254/24",
				Evidence: ir.Evidence{
					File: "core-rtr1.set", StartLine: 2, EndLine: 2,
					RawBlock: "set interfaces ge-0/0/0 unit 0 family inet address 10.0.99.254/24", Parser: "test",
				},
			},
			{
				Name: "ge-0/0/3", IPv4: "192.168.50.1/24",
				Evidence: ir.Evidence{
					File: "core-rtr1.set", StartLine: 3, EndLine: 3,
					RawBlock: "set interfaces ge-0/0/3 unit 0 family inet address 192.168.50.1/24", Parser: "test",
				},
			},
		},
	}
}

func evidenceFromCorpus(ev ir.Evidence, fileSuffix, rawContains string) bool {
	if !strings.Contains(ev.File, fileSuffix) || ev.RawBlock == "" {
		return false
	}
	if rawContains == "" {
		return true
	}
	return strings.Contains(strings.ToLower(ev.RawBlock), strings.ToLower(rawContains))
}
