package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"network-compiler/internal/diag"
	"network-compiler/internal/ir"
	pathtrace "network-compiler/internal/path"
)

func TestDiagAPIPing(t *testing.T) {
	runner := diag.NewFakeRunner()
	runner.Set("edge-sw1", "ping 10.0.99.1 repeat 5", diag.RawResult{
		Output:   "!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms",
		ExitCode: 0,
	})
	devices := []ir.Device{{
		Hostname: "edge-sw1", Vendor: "cisco-ios",
		Interfaces: []ir.Interface{{Name: "Vlan10", IPv4: "10.0.10.1 255.255.255.0"}},
	}}
	svc := diag.NewService(devices, runner)
	ts := httptest.NewServer(New(devices).WithDiag(svc).Handler())
	defer ts.Close()

	body := `{"target":"edge-sw1","command":"ping","args":{"dst":"10.0.99.1","count":5},"runner":"ssh"}`
	resp, err := http.Post(ts.URL+"/api/diag", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got diag.DiagResult
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != diag.StatusOK || got.Class != diag.ClassDiagnostic {
		t.Fatalf("result = %#v", got)
	}
}

func TestDiagAPIExecNeedsApproval(t *testing.T) {
	devices := []ir.Device{{Hostname: "edge-fw1", Vendor: "pan-os"}}
	svc := diag.NewService(devices, diag.NewFakeRunner())
	ts := httptest.NewServer(New(devices).WithDiag(svc).Handler())
	defer ts.Close()

	body := `{"target":"edge-fw1","command":"exec","args":{"raw":"show session all filter destination 192.168.50.20"}}`
	resp, err := http.Post(ts.URL+"/api/diag", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got diag.DiagResult
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != diag.StatusNeedsApproval {
		t.Fatalf("result = %#v", got)
	}
}

func TestDiagAPIConfigDenied(t *testing.T) {
	devices := []ir.Device{{Hostname: "edge-sw1", Vendor: "cisco-ios"}}
	svc := diag.NewService(devices, diag.NewFakeRunner())
	ts := httptest.NewServer(New(devices).WithDiag(svc).Handler())
	defer ts.Close()

	body := `{"target":"edge-sw1","command":"exec","args":{"raw":"configure terminal"}}`
	resp, err := http.Post(ts.URL+"/api/diag", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got diag.DiagResult
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != diag.StatusDenied || got.Class != diag.ClassConfig {
		t.Fatalf("result = %#v", got)
	}
}

func TestPathValidateAPI(t *testing.T) {
	devices := diagValidateDevices()
	runner := diag.NewFakeRunner()
	scriptValidateReachable(runner)
	svc := diag.NewService(devices, runner)
	ts := httptest.NewServer(New(devices).WithDiag(svc).Handler())
	defer ts.Close()

	body := `{"src":"10.0.10.55","dst":"192.168.50.20","proto":"tcp","dport":443,"runner":"ssh"}`
	resp, err := http.Post(ts.URL+"/api/path/validate", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got diag.PathValidation
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Agreement != diag.AgreementMatch || got.PredictedVerdict != pathtrace.VerdictDelivered {
		t.Fatalf("validation = %#v", got)
	}
}

func TestDiagAPIMethodNotAllowed(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/diag")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPathValidateAPIBadRequest(t *testing.T) {
	ts := httptest.NewServer(New(nil).Handler())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/api/path/validate", "application/json", bytes.NewReader([]byte(`{"src":"1.1.1.1"}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func diagValidateDevices() []ir.Device {
	ev := ir.Evidence{File: "test", StartLine: 1, EndLine: 1, RawBlock: "test", Parser: "test"}
	return []ir.Device{
		{
			Hostname: "edge-sw1", Vendor: "cisco-ios", Evidence: ev,
			Interfaces: []ir.Interface{
				{Name: "GigabitEthernet1/0/1", IPv4: "10.0.10.1 255.255.255.0", Evidence: ev},
				{Name: "GigabitEthernet1/0/24", IPv4: "10.0.99.2 255.255.255.252", Evidence: ev},
			},
			Routes: []ir.Route{{Destination: "0.0.0.0 0.0.0.0", NextHop: "10.0.99.1", Evidence: ev}},
		},
		{
			Hostname: "core-rtr1", Vendor: "juniper", Evidence: ev,
			Interfaces: []ir.Interface{
				{Name: "ge-0/0/0", IPv4: "10.0.99.1/30", Evidence: ev},
				{Name: "ge-0/0/3", IPv4: "10.0.99.253/30", Evidence: ev},
			},
			Routes: []ir.Route{{Destination: "192.168.50.0/24", NextHop: "10.0.99.254", Evidence: ev}},
		},
		{
			Hostname: "edge-fw1", Vendor: "pan-os", Evidence: ev,
			Interfaces: []ir.Interface{
				{Name: "ethernet1/2", IPv4: "10.0.99.254/30", Evidence: ev},
				{Name: "ethernet1/1.99", IPv4: "192.168.50.1/24", Evidence: ev},
			},
			Zones: []ir.Zone{
				{Name: "trust", Interfaces: []string{"ethernet1/2"}, Evidence: ev},
				{Name: "dmz", Interfaces: []string{"ethernet1/1.99"}, Evidence: ev},
			},
			SecurityPolicies: []ir.SecurityPolicy{
				{Name: "users-to-lab", FromZone: "trust", ToZone: "dmz", Service: "tcp-443", Action: "allow", Evidence: ev},
			},
		},
	}
}

func scriptValidateReachable(runner *diag.FakeRunner) {
	ok := diag.RawResult{
		Output:   "!!!\nSuccess rate is 100 percent (3/3), round-trip min/avg/max = 1/2/3 ms",
		ExitCode: 0,
	}
	for host, cmd := range map[string]string{
		"edge-sw1":  "ping 10.0.99.1 repeat 3",
		"core-rtr1": "ping 10.0.99.254 count 3",
		"edge-fw1":  "ping host 192.168.50.20 count 3",
	} {
		runner.Set(host, cmd, ok)
	}
}
