package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"network-compiler/internal/ir"
	pathtrace "network-compiler/internal/path"
	"network-compiler/internal/query"
	"network-compiler/internal/server"
	"network-compiler/internal/store"
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
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Type != "interface" || rows[0].Device != "sw1" || rows[0].Summary != "GigabitEthernet1/0/1 access vlan 42" || rows[0].Evidence.StartLine == 0 {
		t.Fatalf("unexpected first row: %#v", rows[0])
	}
}

func TestPathCommandJSONAndText(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "store.jsonl")
	if err := store.WriteJSONL(storePath, cliPathDevices()); err != nil {
		t.Fatal(err)
	}
	jsonOut := captureStdout(t, func() {
		if err := run([]string{"path", "--store", storePath, "--src", "10.0.10.55", "--dst", "192.168.50.20", "--proto", "tcp", "--dport", "443", "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	var got pathtrace.Path
	if err := json.Unmarshal(jsonOut, &got); err != nil {
		t.Fatal(err)
	}
	if got.Verdict != pathtrace.VerdictDelivered || len(got.Hops) != 2 {
		t.Fatalf("path = %#v", got)
	}

	textOut := captureStdout(t, func() {
		if err := run([]string{"path", "--store", storePath, "--src", "10.0.10.55", "--dst", "192.168.50.20", "--proto", "tcp", "--dport", "443"}); err != nil {
			t.Fatal(err)
		}
	})
	text := string(textOut)
	if !strings.Contains(text, "1. edge1 ingress=lan10 egress=to-core next_hop=10.0.12.2 route=192.168.50.0/24") {
		t.Fatalf("text missing hop: %q", text)
	}
	if !strings.Contains(text, "verdict=delivered") {
		t.Fatalf("text missing verdict: %q", text)
	}
}

func TestPathCommandJSONMatchesAPI(t *testing.T) {
	devices := cliPathDevices()
	storePath := filepath.Join(t.TempDir(), "store.jsonl")
	if err := store.WriteJSONL(storePath, devices); err != nil {
		t.Fatal(err)
	}
	cliOut := captureStdout(t, func() {
		if err := run([]string{"path", "--store", storePath, "--src", "10.0.10.55", "--dst", "192.168.50.20", "--proto", "tcp", "--dport", "443", "--json"}); err != nil {
			t.Fatal(err)
		}
	})

	req := httptest.NewRequest("GET", "/api/path?src=10.0.10.55&dst=192.168.50.20&proto=tcp&dport=443", nil)
	rec := httptest.NewRecorder()
	server.New(devices).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(cliOut) {
		t.Fatalf("api JSON differs from CLI JSON\n--- api ---\n%s\n--- cli ---\n%s", rec.Body.String(), cliOut)
	}
}

func TestDiscoverCommandWritesStableJSONL(t *testing.T) {
	out := filepath.Join(t.TempDir(), "discovery.jsonl")
	if err := run([]string{"discover", "--input", "../../testdata/discovery", "--out", out}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 23 {
		t.Fatalf("jsonl lines = %d, want 23\n%s", len(lines), data)
	}
	var first ir.DiscoveryFact
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.Type != "neighbor" || first.Status != "candidate" || first.Evidence.File == "" {
		t.Fatalf("unexpected first fact: %#v", first)
	}
}

func TestDiscoverCommandSummary(t *testing.T) {
	out := captureStdout(t, func() {
		if err := run([]string{"discover", "--input", "../../testdata/discovery", "--summary"}); err != nil {
			t.Fatal(err)
		}
	})
	text := string(out)
	if !strings.Contains(text, "devices=4 neighbors=10 candidate_links=8 conflicts=1") {
		t.Fatalf("summary = %q", text)
	}
	if !strings.Contains(text, "sw1 Gi1/0/1 -> sw2 Gi0/1 confidence=0.95 sources=cdp,lldp") {
		t.Fatalf("summary missing merged link: %q", text)
	}
	if !strings.Contains(text, "sw1 Gi1/0/4 -> sw5 Gi0/4 confidence=0.35 sources=interface_description") {
		t.Fatalf("summary missing weak description link: %q", text)
	}
}

func TestCollectRunSimulate(t *testing.T) {
	planOut := filepath.Join(t.TempDir(), "collect-plan.json")
	if err := run([]string{"collect", "plan", "--targets", "../../testdata/guard/targets.jsonl", "--guard", "../../testdata/guard/guard.yaml", "--out", planOut}); err != nil {
		t.Fatal(err)
	}
	planData, err := os.ReadFile(planOut)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(planData, &plan); err != nil {
		t.Fatal(err)
	}
	collectOut := filepath.Join(t.TempDir(), "collect-out")
	if err := run([]string{"collect", "run", "--plan", planOut, "--confirm-plan-sha256", plan.SHA256, "--out", collectOut, "--simulate"}); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(collectOut, "sw1", "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), `"source":"collect"`) {
		t.Fatalf("metadata = %q", md)
	}
	if _, err := os.Stat(filepath.Join(collectOut, "sw1", "show-lldp-neighbors-detail.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(collectOut, "sw1", "show-arp.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestCollectIngestFromSimulateOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "collect-out")
	if err := os.MkdirAll(filepath.Join(root, "sw1"), 0755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("../../internal/collect/simulate/sw1/show-running-config.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sw1", "show-running-config.txt"), src, 0644); err != nil {
		t.Fatal(err)
	}
	inventoryOut := filepath.Join(t.TempDir(), "inventory.jsonl")
	if err := run([]string{"collect", "ingest", "--input", root, "--out", inventoryOut, "--vendor", "cisco"}); err != nil {
		t.Fatal(err)
	}
	devices, err := store.ReadJSONL(inventoryOut)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Hostname != "sw1" {
		t.Fatalf("devices = %#v", devices)
	}
}

func TestCollectPlanAndVerify(t *testing.T) {
	out := filepath.Join(t.TempDir(), "collect-plan.json")
	stdout := captureStdout(t, func() {
		if err := run([]string{"collect", "plan", "--targets", "../../testdata/guard/targets.jsonl", "--guard", "../../testdata/guard/guard.yaml", "--out", out, "--summary"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(string(stdout), "targets=5 allowed=1 rejected=4") {
		t.Fatalf("summary = %q", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	if plan.SHA256 == "" {
		t.Fatal("missing plan hash")
	}
	verifyOut := captureStdout(t, func() {
		if err := run([]string{"collect", "verify", "--plan", out, "--confirm-plan-sha256", plan.SHA256}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(string(verifyOut), "verified plan") {
		t.Fatalf("verify output = %q", verifyOut)
	}
}

func cliPathDevices() []ir.Device {
	return []ir.Device{
		{
			Hostname: "edge1",
			Vendor:   "cisco",
			Interfaces: []ir.Interface{
				{Name: "lan10", Mode: "routed", IPv4: "10.0.10.1/24", Evidence: cliEvidence("edge1.cfg", 10, "interface lan10")},
				{Name: "to-core", Mode: "routed", IPv4: "10.0.12.1/30", Evidence: cliEvidence("edge1.cfg", 20, "interface to-core")},
			},
			Routes: []ir.Route{
				{Destination: "192.168.50.0/24", NextHop: "10.0.12.2", Interface: "to-core", Evidence: cliEvidence("edge1.cfg", 30, "ip route 192.168.50.0/24 10.0.12.2")},
			},
			Evidence: cliEvidence("edge1.cfg", 1, "hostname edge1"),
		},
		{
			Hostname: "core1",
			Vendor:   "cisco",
			Interfaces: []ir.Interface{
				{Name: "to-edge", Mode: "routed", IPv4: "10.0.12.2/30", Evidence: cliEvidence("core1.cfg", 10, "interface to-edge")},
				{Name: "server50", Mode: "routed", IPv4: "192.168.50.1/24", Evidence: cliEvidence("core1.cfg", 20, "interface server50")},
			},
			Evidence: cliEvidence("core1.cfg", 1, "hostname core1"),
		},
	}
}

func cliEvidence(file string, line int, raw string) ir.Evidence {
	return ir.Evidence{File: file, StartLine: line, EndLine: line, RawBlock: raw, Parser: "test"}
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

func TestLoadDevicesMissingInventory(t *testing.T) {
	_, err := loadDevices("cisco", filepath.Join(t.TempDir(), "missing.jsonl"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "inventaire introuvable") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "netc ingest") {
		t.Fatalf("err missing ingest hint: %v", err)
	}
}
