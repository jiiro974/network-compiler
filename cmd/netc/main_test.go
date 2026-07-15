package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"network-compiler/internal/ir"
	"network-compiler/internal/query"
)

func TestQueryInputsWithShellExpandedFiles(t *testing.T) {
	inputs, queryText, err := queryInputs("../../testdata/cisco-sw1.cfg", []string{
		"../../internal/parser/cisco/testdata/sample_ios.cfg",
		"vlan 2048",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Fatalf("inputs = %d, want 2", len(inputs))
	}
	if queryText != "vlan 2048" {
		t.Fatalf("query = %q, want vlan 2048", queryText)
	}
}

func TestQueryInputsWithDirectory(t *testing.T) {
	inputs, queryText, err := queryInputs("../../testdata", []string{"find interfaces trunk"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatal("inputs is empty")
	}
	if queryText != "find interfaces trunk" {
		t.Fatalf("query = %q", queryText)
	}
}

func TestLoadDevicesFromJSONLInventory(t *testing.T) {
	out := filepath.Join(t.TempDir(), "inventory.jsonl")
	if err := run([]string{"ingest", "--input", "../../testdata", "--out", out}); err != nil {
		t.Fatal(err)
	}
	devices, err := loadDevices("cisco", out)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 {
		t.Fatal("devices is empty")
	}
	found := false
	for _, dev := range devices {
		if dev.Hostname == "sw1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("sw1 not found in %#v", devices)
	}
}

func TestBriefResultsDropsFullObject(t *testing.T) {
	results := []query.Result{
		{Type: "vlan", Device: "sw1", Summary: "vlan 42"},
	}
	brief := briefResults(results)
	if len(brief) != 1 {
		t.Fatalf("brief results = %d", len(brief))
	}
	if brief[0].Summary != "vlan 42" {
		t.Fatalf("summary = %q", brief[0].Summary)
	}
}

func TestPolicyFromFlagsLoadsFileAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	data := []byte(`{"required_ntp_servers":["10.0.0.1"],"required_syslog_hosts":["10.0.1.1"]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := policyFromFlags(path, "10.0.0.2", "", "public")
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.RequiredNTPServers) != 1 || policy.RequiredNTPServers[0] != "10.0.0.2" {
		t.Fatalf("ntp = %#v", policy.RequiredNTPServers)
	}
	if len(policy.RequiredSyslogHosts) != 1 || policy.RequiredSyslogHosts[0] != "10.0.1.1" {
		t.Fatalf("syslog = %#v", policy.RequiredSyslogHosts)
	}
	if len(policy.ForbiddenSNMPCommunities) != 1 || policy.ForbiddenSNMPCommunities[0] != "public" {
		t.Fatalf("snmp = %#v", policy.ForbiddenSNMPCommunities)
	}
}

func TestGoldenParseCiscoFixture(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run([]string{"parse", "--vendor", "cisco", "../../testdata/cisco-sw1.cfg"}); err != nil {
			t.Fatal(err)
		}
	})
	var dev ir.Device
	if err := json.Unmarshal(out, &dev); err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "sw1" || dev.Vendor != "cisco" {
		t.Fatalf("device identity = %s/%s", dev.Vendor, dev.Hostname)
	}
	if len(dev.Interfaces) != 3 || len(dev.VLANs) != 2 || len(dev.Routes) != 1 || len(dev.ACLs) != 2 {
		t.Fatalf("unexpected inventory sizes: if=%d vlans=%d routes=%d acls=%d", len(dev.Interfaces), len(dev.VLANs), len(dev.Routes), len(dev.ACLs))
	}
	if dev.Interfaces[1].Evidence.File == "" || dev.Interfaces[1].Evidence.RawBlock == "" {
		t.Fatalf("missing interface evidence: %#v", dev.Interfaces[1].Evidence)
	}
	if len(dev.Services.NTPServers) != 1 || len(dev.Services.SyslogHosts) != 1 || len(dev.Services.SNMPCommunities) != 1 {
		t.Fatalf("unexpected services: %#v", dev.Services)
	}
}

func TestGoldenQueryCiscoFixture(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run([]string{"query", "--input", "../../testdata/cisco-sw1.cfg", "--brief", "vlan 42"}); err != nil {
			t.Fatal(err)
		}
	})
	var rows []briefResult
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].Type != "vlan" || rows[0].Device != "sw1" || rows[0].Evidence.StartLine == 0 {
		t.Fatalf("unexpected first row: %#v", rows[0])
	}
}

func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
