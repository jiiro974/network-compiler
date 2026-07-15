package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"network-compiler/internal/compliance"
	"network-compiler/internal/diff"
	"network-compiler/internal/ir"
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
