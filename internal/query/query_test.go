package query

import (
	"strings"
	"testing"

	"network-compiler/internal/ir"
	"network-compiler/internal/parser/cisco"
)

func TestRunSupportedQueries(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		query     string
		wantType  string
		wantCount int
	}{
		{name: "vlan", query: "find vlan 42", wantType: "interface", wantCount: 2},
		{name: "interface", query: "find interface GigabitEthernet1/0/1", wantType: "interface", wantCount: 1},
		{name: "interfaces trunk", query: "find interfaces trunk", wantType: "interface", wantCount: 1},
		{name: "interfaces access vlan", query: "find interfaces access vlan 42", wantType: "interface", wantCount: 1},
		{name: "default route", query: "find default route", wantType: "route", wantCount: 1},
		{name: "acl", query: "find acl 101", wantType: "acl", wantCount: 1},
		{name: "device", query: "find device sw1", wantType: "device", wantCount: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := Run([]ir.Device{dev}, tt.query)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := len(results); got != tt.wantCount {
				t.Fatalf("len(results) = %d, want %d", got, tt.wantCount)
			}
			if results[0].Type != tt.wantType {
				t.Fatalf("Type = %q, want %q", results[0].Type, tt.wantType)
			}
			if results[0].Evidence.StartLine == 0 {
				t.Fatalf("Evidence is empty")
			}
			if results[0].Summary == "" {
				t.Fatalf("Summary is empty")
			}
		})
	}
}

func TestRunNotFound(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	results, err := Run([]ir.Device{dev}, "find vlan 404")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}

func TestRunVLANPrefersLocalUsageOverDeclarations(t *testing.T) {
	devices := []ir.Device{
		vlanFixtureDevice("sw-declared-only", nil, []ir.Interface{}),
		vlanFixtureDevice("sw-access", nil, []ir.Interface{
			{Name: "Gi1/0/10", Mode: "access", AccessVLAN: 2048, Evidence: ev("sw-access.cfg", 10, "interface Gi1/0/10\n switchport mode access\n switchport access vlan 2048")},
		}),
		vlanFixtureDevice("sw-trunk-explicit", nil, []ir.Interface{
			{Name: "Gi1/0/48", Mode: "trunk", TrunkVLANs: []int{10, 2048, 2050}, Evidence: ev("sw-trunk-explicit.cfg", 20, "interface Gi1/0/48\n switchport mode trunk\n switchport trunk allowed vlan 10,2048,2050")},
		}),
		vlanFixtureDevice("sw-trunk-broad", nil, []ir.Interface{
			{Name: "Gi1/0/49", Mode: "trunk", TrunkVLANs: vlanRange(1, 4094), Evidence: ev("sw-trunk-broad.cfg", 30, "interface Gi1/0/49\n switchport mode trunk\n switchport trunk allowed vlan 1-4094")},
		}),
	}

	results, err := Run(devices, "vlan 2048")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(results), 3; got != want {
		t.Fatalf("len(results) = %d, want %d: %#v", got, want, results)
	}
	wantRoles := []string{"access", "trunk", "trunk_broad"}
	wantDevices := []string{"sw-access", "sw-trunk-explicit", "sw-trunk-broad"}
	for i := range wantRoles {
		if results[i].Role != wantRoles[i] || results[i].Device != wantDevices[i] {
			t.Fatalf("result[%d] = role=%q device=%q, want role=%q device=%q", i, results[i].Role, results[i].Device, wantRoles[i], wantDevices[i])
		}
		if results[i].Evidence.StartLine == 0 || results[i].Evidence.RawBlock == "" {
			t.Fatalf("result[%d] missing evidence: %#v", i, results[i].Evidence)
		}
	}
}

func TestRunVLANSubqueries(t *testing.T) {
	devices := []ir.Device{
		vlanFixtureDevice("sw-a", nil, []ir.Interface{
			{Name: "Gi1/0/10", Mode: "access", AccessVLAN: 2048, Evidence: ev("sw-a.cfg", 10, "interface Gi1/0/10\n switchport access vlan 2048")},
		}),
		vlanFixtureDevice("sw-b", nil, []ir.Interface{
			{Name: "Gi1/0/48", Mode: "trunk", TrunkVLANs: []int{100, 2048}, Evidence: ev("sw-b.cfg", 20, "interface Gi1/0/48\n switchport trunk allowed vlan 100,2048")},
			{Name: "Gi1/0/49", Mode: "trunk", TrunkVLANs: vlanRange(1, 4094), Evidence: ev("sw-b.cfg", 30, "interface Gi1/0/49\n switchport trunk allowed vlan 1-4094")},
		}),
	}

	tests := []struct {
		query string
		roles []string
	}{
		{query: "vlan 2048 access", roles: []string{"access"}},
		{query: "vlan 2048 trunks", roles: []string{"trunk", "trunk_broad"}},
		{query: "vlan 2048 declared", roles: []string{"declared", "declared"}},
		{query: "vlan 2048 active", roles: []string{"access", "trunk", "trunk_broad"}},
		{query: "vlan 2048 used", roles: []string{"access", "trunk", "trunk_broad"}},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			results, err := Run(devices, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != len(tt.roles) {
				t.Fatalf("len(results) = %d, want %d: %#v", len(results), len(tt.roles), results)
			}
			for i, role := range tt.roles {
				if results[i].Role != role {
					t.Fatalf("result[%d].Role = %q, want %q", i, results[i].Role, role)
				}
			}
		})
	}
}

func TestRunVLANFallsBackToDeclarationsWhenUnused(t *testing.T) {
	devices := []ir.Device{
		vlanFixtureDevice("sw-a", nil, nil),
		vlanFixtureDevice("sw-b", nil, nil),
	}
	results, err := Run(devices, "vlan 2048")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, result := range results {
		if result.Role != "declared" || result.Type != "vlan" {
			t.Fatalf("result = role=%q type=%q, want declared vlan", result.Role, result.Type)
		}
	}
}

func TestRunUnsupportedQuery(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run([]ir.Device{dev}, "show vlan 10")
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "requete non reconnue") {
		t.Fatalf("error = %q, want unrecognized query message", err.Error())
	}
	if !strings.Contains(err.Error(), "help") {
		t.Fatalf("error = %q, want help suggestion", err.Error())
	}
}

func TestRunHelpQuery(t *testing.T) {
	results, err := Run([]ir.Device{{Hostname: "sw1"}}, "help")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(HelpPatterns()) {
		t.Fatalf("len(results) = %d, want %d", len(results), len(HelpPatterns()))
	}
	for _, result := range results {
		if result.Type != "help" || result.Summary == "" {
			t.Fatalf("result = %#v, want help summary", result)
		}
	}
}

func TestRunNaturalLanguageSynonyms(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}

	synonyms := map[string]string{
		"ou est vlan 42":   "vlan 42",
		"where is vlan 42": "vlan 42",
		"route par defaut": "default route",
		"trunk ports":      "interfaces trunk",
		"serveurs ntp":     "ntp",
		"logging":          "syslog",
		"access-list 101":  "acl 101",
		"host sw1":         "device sw1",
	}
	for alt, canonical := range synonyms {
		t.Run(alt, func(t *testing.T) {
			altResults, err := Run([]ir.Device{dev}, alt)
			if err != nil {
				t.Fatal(err)
			}
			canonicalResults, err := Run([]ir.Device{dev}, canonical)
			if err != nil {
				t.Fatal(err)
			}
			if len(altResults) != len(canonicalResults) {
				t.Fatalf("len(alt)=%d len(canonical)=%d", len(altResults), len(canonicalResults))
			}
			for i := range altResults {
				if altResults[i].Type != canonicalResults[i].Type || altResults[i].Summary != canonicalResults[i].Summary {
					t.Fatalf("alt[%d]=%#v canonical[%d]=%#v", i, altResults[i], i, canonicalResults[i])
				}
			}
		})
	}
}

func TestRunServiceQueries(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		query    string
		wantType string
		wantVal  string
	}{
		{query: "ntp", wantType: "ntp", wantVal: "10.10.10.1"},
		{query: "syslog", wantType: "syslog", wantVal: "10.10.20.5"},
		{query: "snmp", wantType: "snmp", wantVal: "public"},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			results, err := Run([]ir.Device{dev}, tt.query)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("len(results) = %d, want 1", len(results))
			}
			if results[0].Type != tt.wantType {
				t.Fatalf("Type = %q, want %q", results[0].Type, tt.wantType)
			}
			if !strings.Contains(results[0].Summary, tt.wantVal) {
				t.Fatalf("Summary = %q, want value %q", results[0].Summary, tt.wantVal)
			}
			if results[0].Evidence.StartLine == 0 {
				t.Fatal("missing evidence")
			}
		})
	}
}

func TestRunInvalidVLAN(t *testing.T) {
	dev, err := cisco.New().ParseFile("../../testdata/cisco-sw1.cfg")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run([]ir.Device{dev}, "find vlan abc")
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "vlan invalide") {
		t.Fatalf("error = %q, want invalid vlan message", err.Error())
	}
}

func vlanFixtureDevice(hostname string, vlans []ir.VLAN, interfaces []ir.Interface) ir.Device {
	if vlans == nil {
		vlans = []ir.VLAN{{ID: 2048, Name: "USERS-2048", Evidence: ev(hostname+".cfg", 3, "vlan 2048\n name USERS-2048")}}
	}
	return ir.Device{Hostname: hostname, VLANs: vlans, Interfaces: interfaces}
}

func ev(file string, start int, raw string) ir.Evidence {
	return ir.Evidence{File: file, StartLine: start, EndLine: start + strings.Count(raw, "\n"), RawBlock: raw, Parser: "test"}
}

func vlanRange(start, end int) []int {
	out := make([]int, 0, end-start+1)
	for id := start; id <= end; id++ {
		out = append(out, id)
	}
	return out
}
