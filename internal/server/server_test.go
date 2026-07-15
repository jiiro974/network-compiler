package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"network-compiler/internal/compliance"
	"network-compiler/internal/diff"
	"network-compiler/internal/ir"
	pathtrace "network-compiler/internal/path"
)

func TestQueryAPI(t *testing.T) {
	devices := []ir.Device{
		{
			Hostname: "sw1",
			VLANs: []ir.VLAN{
				{ID: 42, Name: "USERS", Evidence: ir.Evidence{File: "sw1.cfg", StartLine: 1, EndLine: 3}},
			},
		},
	}
	ts := httptest.NewServer(New(devices).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/query?q=vlan%2042&brief=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var rows []briefResult
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Device != "sw1" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestVLANPathAPIUsesDiscoveryLinks(t *testing.T) {
	devices := []ir.Device{
		{
			Hostname: "sw1",
			Interfaces: []ir.Interface{
				{Name: "Gi1/0/1", Mode: "trunk", TrunkVLANs: []int{42}, Evidence: ir.Evidence{File: "sw1.cfg", StartLine: 10, EndLine: 12}},
				{Name: "Gi1/0/2", Mode: "access", AccessVLAN: 42, Evidence: ir.Evidence{File: "sw1.cfg", StartLine: 20, EndLine: 22}},
			},
		},
		{
			Hostname: "sw2",
			Interfaces: []ir.Interface{
				{Name: "Gi0/1", Mode: "trunk", TrunkVLANs: []int{42}, Evidence: ir.Evidence{File: "sw2.cfg", StartLine: 30, EndLine: 32}},
			},
		},
	}
	facts := []ir.DiscoveryFact{{
		Type: "link",
		Link: &ir.Link{
			A:          ir.LinkEndpoint{Device: "sw1", Interface: "Gi1/0/1"},
			B:          ir.LinkEndpoint{Device: "sw2", Interface: "Gi0/1"},
			Sources:    []string{"cdp", "lldp"},
			Confidence: 0.95,
			Status:     ir.StatusCandidate,
		},
	}}
	ts := httptest.NewServer(New(devices).WithDiscoveryFacts(facts).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/vlan-path?vlan=42")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got vlanPathResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Devices != 2 || got.Summary.PhysicalLinks != 1 || len(got.Edges) != 1 {
		t.Fatalf("path = %#v", got)
	}
	if got.Edges[0].Confidence != 0.95 || got.Edges[0].Sources[0] != "cdp" {
		t.Fatalf("edge = %#v", got.Edges[0])
	}
}

func TestPathAPI(t *testing.T) {
	ts := httptest.NewServer(New(serverPathDevices()).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/path?src=10.0.10.55&dst=192.168.50.20&proto=tcp&dport=443")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got pathtrace.Path
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Verdict != pathtrace.VerdictDelivered || len(got.Hops) != 2 {
		t.Fatalf("path = %#v", got)
	}
	if got.Hops[0].RouteMatch == nil || got.Hops[0].RouteMatch.NextHop != "10.0.12.2" {
		t.Fatalf("first hop = %#v", got.Hops[0])
	}
}

func TestPathPage(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/path")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "netc path") || !strings.Contains(string(body), "/api/path") || !strings.Contains(string(body), "Valider le chemin") || !strings.Contains(string(body), "Copy validation JSON") {
		t.Fatalf("path page body missing expected content")
	}
}

func TestPathFixtureHandlers(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	for _, name := range []string{"delivered.json", "no_route.json", "dropped_acl.json", "dropped_policy.json", "loop.json"} {
		resp, err := http.Get(ts.URL + "/path/fixtures/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("%s status = %d", name, resp.StatusCode)
		}
		var got pathtrace.Path
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			resp.Body.Close()
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		if got.Verdict == "" || got.Flow.Src == "" || len(got.Hops) == 0 {
			t.Fatalf("%s fixture incomplete: %#v", name, got)
		}
	}

	for _, name := range []string{
		"diag/ping_ok.json",
		"diag/exec_needs_approval.json",
		"diag/config_denied.json",
		"diag/path_validate_match.json",
		"diag/path_validate_mismatch.json",
	} {
		resp, err := http.Get(ts.URL + "/path/fixtures/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("%s status = %d", name, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 {
			t.Fatalf("%s fixture empty", name)
		}
	}
}

func TestPathFixturesConformToContract(t *testing.T) {
	want := map[pathtrace.Verdict]string{
		pathtrace.VerdictDelivered:     "delivered.json",
		pathtrace.VerdictNoRoute:       "no_route.json",
		pathtrace.VerdictDroppedACL:    "dropped_acl.json",
		pathtrace.VerdictDroppedPolicy: "dropped_policy.json",
		pathtrace.VerdictLoop:          "loop.json",
	}
	seenFirewall := false
	for verdict, name := range want {
		data, err := os.ReadFile(filepath.Join("assets", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		var got pathtrace.Path
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Verdict != verdict {
			t.Fatalf("%s verdict = %s, want %s", name, got.Verdict, verdict)
		}
		if got.Flow.Src == "" || got.Flow.Dst == "" || got.Flow.Proto == "" {
			t.Fatalf("%s missing flow fields: %#v", name, got.Flow)
		}
		if got.Reason == nil || got.Reason.File == "" || got.Reason.RawBlock == "" {
			t.Fatalf("%s missing reason evidence: %#v", name, got.Reason)
		}
		if len(got.Hops) == 0 {
			t.Fatalf("%s has no hops", name)
		}
		for _, hop := range got.Hops {
			if hop.Device == "" || hop.Vendor == "" || hop.IngressIface == "" {
				t.Fatalf("%s incomplete hop: %#v", name, hop)
			}
			if hop.PolicyMatch != nil && hop.IngressZone != "" && hop.EgressZone != "" {
				seenFirewall = true
			}
		}
	}
	if !seenFirewall {
		t.Fatal("fixtures do not cover firewall policy with zones")
	}
}

func TestCheckAndDeviceAPI(t *testing.T) {
	devices := []ir.Device{
		{
			Hostname: "sw1",
			Evidence: ir.Evidence{File: "sw1.cfg", StartLine: 1, EndLine: 1},
			Services: ir.Services{
				NTPServers: []ir.ServiceTarget{{Value: "10.0.0.1"}},
			},
		},
	}
	ts := httptest.NewServer(New(devices).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/check/summary?ntp=10.0.0.1,10.0.0.2&syslog=10.0.1.1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("summary status = %d", resp.StatusCode)
	}
	var summary struct {
		Findings int `json:"findings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Findings != 2 {
		t.Fatalf("findings = %d, want 2", summary.Findings)
	}

	resp, err = http.Get(ts.URL + "/api/device?brief=1&name=sw1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device status = %d", resp.StatusCode)
	}
	var dev deviceSummaryRow
	if err := json.NewDecoder(resp.Body).Decode(&dev); err != nil {
		t.Fatal(err)
	}
	if dev.Hostname != "sw1" {
		t.Fatalf("hostname = %q", dev.Hostname)
	}
	if len(dev.NTPServers) != 1 || dev.NTPServers[0] != "10.0.0.1" {
		t.Fatalf("ntp servers = %#v", dev.NTPServers)
	}
}

func serverPathDevices() []ir.Device {
	return []ir.Device{
		{
			Hostname: "edge1",
			Vendor:   "cisco",
			Interfaces: []ir.Interface{
				{Name: "lan10", Mode: "routed", IPv4: "10.0.10.1/24", Evidence: serverEvidence("edge1.cfg", 10, "interface lan10")},
				{Name: "to-core", Mode: "routed", IPv4: "10.0.12.1/30", Evidence: serverEvidence("edge1.cfg", 20, "interface to-core")},
			},
			Routes: []ir.Route{
				{Destination: "192.168.50.0/24", NextHop: "10.0.12.2", Interface: "to-core", Evidence: serverEvidence("edge1.cfg", 30, "ip route 192.168.50.0/24 10.0.12.2")},
			},
			Evidence: serverEvidence("edge1.cfg", 1, "hostname edge1"),
		},
		{
			Hostname: "core1",
			Vendor:   "cisco",
			Interfaces: []ir.Interface{
				{Name: "to-edge", Mode: "routed", IPv4: "10.0.12.2/30", Evidence: serverEvidence("core1.cfg", 10, "interface to-edge")},
				{Name: "server50", Mode: "routed", IPv4: "192.168.50.1/24", Evidence: serverEvidence("core1.cfg", 20, "interface server50")},
			},
			Evidence: serverEvidence("core1.cfg", 1, "hostname core1"),
		},
	}
}

func serverEvidence(file string, line int, raw string) ir.Evidence {
	return ir.Evidence{File: file, StartLine: line, EndLine: line, RawBlock: raw, Parser: "test"}
}

func TestCheckAPIUsesDefaultPolicyAndAllowsOverride(t *testing.T) {
	devices := []ir.Device{{Hostname: "sw1", Evidence: ir.Evidence{File: "sw1.cfg"}}}
	ts := httptest.NewServer(New(devices, compliance.Policy{
		RequiredNTPServers: []string{"10.0.0.1"},
	}).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/check/summary")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var summary compliance.Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Findings != 1 {
		t.Fatalf("default policy findings = %d, want 1", summary.Findings)
	}

	resp, err = http.Get(ts.URL + "/api/check/summary?ntp=")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Findings != 1 {
		t.Fatalf("empty override should keep default, findings = %d", summary.Findings)
	}

	resp, err = http.Get(ts.URL + "/api/check/summary?ntp=10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if summary.Findings != 1 {
		t.Fatalf("override findings = %d, want 1", summary.Findings)
	}
}

func TestPolicyAPI(t *testing.T) {
	ts := httptest.NewServer(New(nil, compliance.Policy{
		RequiredNTPServers: []string{"10.0.0.1"},
	}).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var policy compliance.Policy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.RequiredNTPServers) != 1 || policy.RequiredNTPServers[0] != "10.0.0.1" {
		t.Fatalf("policy = %#v", policy)
	}
}

func TestVendorsAPI(t *testing.T) {
	ts := httptest.NewServer(New(nil).WithVendors([]string{"cisco", "juniper"}).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/vendors")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var vendors []string
	if err := json.NewDecoder(resp.Body).Decode(&vendors); err != nil {
		t.Fatal(err)
	}
	if len(vendors) != 2 || vendors[1] != "juniper" {
		t.Fatalf("vendors = %#v", vendors)
	}
}

func TestDevicesAPIFilter(t *testing.T) {
	devices := []ir.Device{
		{Hostname: "sw-core-1", SourceFile: "sw-core-1.cfg"},
		{Hostname: "sw-edge-1", SourceFile: "sw-edge-1.cfg"},
	}
	ts := httptest.NewServer(New(devices).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/devices?q=edge")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rows []struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Hostname != "sw-edge-1" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestDiffAPI(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before.cfg")
	afterPath := filepath.Join(dir, "after.cfg")
	before := []byte("hostname sw1\n!\nvlan 10\n name OLD\n!\n")
	after := []byte("hostname sw1\n!\nvlan 10\n name NEW\n!\n")
	if err := os.WriteFile(beforePath, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(afterPath, after, 0600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/diff?before=" + beforePath + "&after=" + afterPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var changes []diff.Change
	if err := json.NewDecoder(resp.Body).Decode(&changes); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Object != "vlan:10" {
		t.Fatalf("changes = %#v", changes)
	}
}

func TestIndexHTMLContainsDiffModes(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, want := range []string{
		"brand-mark",
		"netc.theme",
		"nav-link nav-active",
		`href="/path"`,
		"data-diff-mode=\"normalized\"",
		"data-diff-mode=\"table\"",
		"data-diff-sub=\"config\"",
		"function evidenceHighlightPre",
		"function diffTypeClass",
		"diff-type-badge",
		"norm-section",
		".code-line.match",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("index HTML missing %q", want)
		}
	}
}

func TestDiffAPIReturnsEmptyArrayForNoChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same.cfg")
	data := []byte("hostname sw1\n!\nvlan 10\n name USERS\n!\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/diff?before=" + path + "&after=" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var changes []diff.Change
	if err := json.NewDecoder(resp.Body).Decode(&changes); err != nil {
		t.Fatal(err)
	}
	if changes == nil {
		t.Fatal("changes is nil")
	}
	if len(changes) != 0 {
		t.Fatalf("changes = %#v", changes)
	}
}
