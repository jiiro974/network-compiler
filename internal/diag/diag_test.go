package diag

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"network-compiler/internal/ir"
	pathtrace "network-compiler/internal/path"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		cmd, raw, want string
	}{
		{"ping", "", ClassDiagnostic},
		{"show", "show ip route", ClassDiagnostic},
		{"exec", "show session all", ClassExec},
		{"exec", "configure terminal", ClassConfig},
		{"exec", "set system host-name x", ClassConfig},
		{"exec", "delete policy x", ClassConfig},
	}
	for _, tt := range tests {
		if got := classifyCommand(tt.cmd, tt.raw); got != tt.want {
			t.Fatalf("classify(%q,%q) = %q, want %q", tt.cmd, tt.raw, got, tt.want)
		}
	}
}

func TestRenderPingByVendor(t *testing.T) {
	tests := []struct {
		vendor, want string
	}{
		{"cisco-ios", "ping 10.0.99.1 repeat 5"},
		{"juniper", "ping 10.0.99.1 count 5"},
		{"pan-os", "ping host 10.0.99.1 count 5"},
		{"mikrotik-routeros", "/ping 10.0.99.1 count=5"},
		{"fortinet-fortigate", "execute ping 10.0.99.1 repeat 5"},
		{"generic", "ping -c 5 10.0.99.1"},
	}
	for _, tt := range tests {
		got := renderPing(tt.vendor, "10.0.99.1", 5, "", "")
		if got != tt.want {
			t.Fatalf("vendor %s = %q, want %q", tt.vendor, got, tt.want)
		}
	}
}

func TestDiagnosePingOK(t *testing.T) {
	runner := NewFakeRunner()
	runner.Set("edge-sw1", "ping 10.0.99.1 repeat 5", RawResult{
		Output:   "!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms",
		ExitCode: 0,
	})
	svc := NewService(pingDevices(), runner)
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:  "edge-sw1",
		Command: "ping",
		Args:    DiagArgs{Dst: "10.0.99.1", Count: 5},
		Runner:  "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q", res.Status)
	}
	if res.Class != ClassDiagnostic {
		t.Fatalf("class = %q", res.Class)
	}
	if res.RenderedCommand != "ping 10.0.99.1 repeat 5" {
		t.Fatalf("rendered = %q", res.RenderedCommand)
	}
	if res.Parsed == nil || res.Parsed.Ping == nil || res.Parsed.Ping.Received != 5 {
		t.Fatalf("parsed = %#v", res.Parsed)
	}
	if res.AuditID == "" {
		t.Fatal("missing audit_id")
	}
}

func TestDiagnoseExecNeedsApproval(t *testing.T) {
	runner := NewFakeRunner()
	svc := NewService(execDevices(), runner)
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:  "edge-fw1",
		Command: "exec",
		Args:    DiagArgs{Raw: "show session all filter destination 192.168.50.20"},
		Runner:  "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusNeedsApproval {
		t.Fatalf("status = %q", res.Status)
	}
	if res.Class != ClassExec {
		t.Fatalf("class = %q", res.Class)
	}
	if res.RawOutput != "" {
		t.Fatalf("should not execute, raw=%q", res.RawOutput)
	}
	if res.Approval == nil || res.Approval.Granted {
		t.Fatalf("approval = %#v", res.Approval)
	}
}

func TestDiagnoseConfigDenied(t *testing.T) {
	runner := NewFakeRunner()
	svc := NewService(pingDevices(), runner)
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:  "edge-sw1",
		Command: "exec",
		Args:    DiagArgs{Raw: "configure terminal"},
		Runner:  "ssh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusDenied || res.Class != ClassConfig {
		t.Fatalf("result = %#v", res)
	}
	if res.RawOutput != "" {
		t.Fatal("config command should not run")
	}
}

func TestDiagnoseExecWithApproval(t *testing.T) {
	runner := NewFakeRunner()
	runner.Set("edge-fw1", "show session all filter destination 192.168.50.20", RawResult{
		Output:   "total sessions: 0",
		ExitCode: 0,
	})
	approvals := NewStaticApprovals(ApprovalRecord{Token: "tok-1", Target: "edge-fw1", ID: "appr-1"})
	svc := NewService(execDevices(), runner, WithApprovals(approvals))
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:        "edge-fw1",
		Command:       "exec",
		Args:          DiagArgs{Raw: "show session all filter destination 192.168.50.20"},
		ApprovalToken: "tok-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusOK || !res.Approval.Granted {
		t.Fatalf("result = %#v", res)
	}
}

func TestDiagnoseRedactsSecrets(t *testing.T) {
	runner := NewFakeRunner()
	runner.Set("edge-sw1", "show running-config", RawResult{
		Output:   "snmp-server community public RO",
		ExitCode: 0,
	})
	svc := NewService(pingDevices(), runner)
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:  "edge-sw1",
		Command: "show",
		Args:    DiagArgs{Raw: "show running-config"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.RawOutput, "[REDACTED]") {
		t.Fatalf("raw not redacted: %q", res.RawOutput)
	}
}

func TestDiagnoseTimeout(t *testing.T) {
	runner := NewFakeRunner()
	runner.FailNext = context.DeadlineExceeded
	svc := NewService(pingDevices(), runner, WithTimeout(time.Millisecond))
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:  "edge-sw1",
		Command: "ping",
		Args:    DiagArgs{Dst: "10.0.99.1"},
	})
	if err == nil && res.Status != StatusTimeout {
		t.Fatalf("status = %q err = %v", res.Status, err)
	}
}

func TestParsePingAndTraceroute(t *testing.T) {
	pingOut := "!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms"
	p := parsePing(pingOut)
	if p == nil || p.Sent != 5 || p.LossPct != 0 {
		t.Fatalf("ping = %#v", p)
	}
	traceOut := " 1  10.0.99.1  1 ms\n 2  192.168.50.20  2 ms\n"
	tr := parseTraceroute(traceOut)
	if tr == nil || len(tr.Hops) != 2 {
		t.Fatalf("trace = %#v", tr)
	}
}

func TestValidatePathMatchAndMismatch(t *testing.T) {
	devices := validatePathDevices()
	flow := pathtrace.Flow{Src: "10.0.10.55", Dst: "192.168.50.20", Proto: "tcp", DPort: 443}

	matchRunner := NewFakeRunner()
	scriptReachable(matchRunner)
	svcMatch := NewService(devices, matchRunner)
	match, err := svcMatch.ValidatePath(context.Background(), flow, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if match.Agreement != AgreementMatch || match.ObservedVerdict != VerdictReachable {
		t.Fatalf("match = %#v", match)
	}
	if len(match.Checks) != 3 {
		t.Fatalf("checks = %d", len(match.Checks))
	}

	mismatchRunner := NewFakeRunner()
	scriptReachable(mismatchRunner)
	mismatchRunner.Set("edge-fw1", "ping host 192.168.50.20 count 3", RawResult{
		Output:   ".....",
		ExitCode: 1,
	})
	svcMismatch := NewService(devices, mismatchRunner)
	mismatch, err := svcMismatch.ValidatePath(context.Background(), flow, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if mismatch.Agreement != AgreementMismatch || mismatch.ObservedVerdict != VerdictUnreachable {
		t.Fatalf("mismatch = %#v", mismatch)
	}
}

func TestGoldenFixturesShape(t *testing.T) {
	root := filepath.Join("..", "server", "assets", "fixtures", "diag")
	for _, name := range []string{"ping_ok.json", "exec_needs_approval.json", "config_denied.json"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		var res DiagResult
		if err := json.Unmarshal(data, &res); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Target == "" || res.Status == "" || res.Class == "" {
			t.Fatalf("%s incomplete: %#v", name, res)
		}
	}
	for _, name := range []string{"path_validate_match.json", "path_validate_mismatch.json"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		var res PathValidation
		if err := json.Unmarshal(data, &res); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Agreement == "" || len(res.Checks) == 0 {
			t.Fatalf("%s incomplete: %#v", name, res)
		}
	}
}

func TestApprovalProviderInvalidToken(t *testing.T) {
	p := NewStaticApprovals()
	approval, err := p.Check("bad", "cmd", Target{Host: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if approval.Granted {
		t.Fatal("expected not granted")
	}
}

func TestResolveTargetIPLiteral(t *testing.T) {
	svc := NewService(nil, NewFakeRunner())
	target, err := svc.resolveTarget("ip:192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if target.Address != "192.168.1.1" || target.Vendor != "generic" {
		t.Fatalf("target = %#v", target)
	}
}

func TestResolveTargetManagementIP(t *testing.T) {
	devices := []ir.Device{{
		Hostname: "edge-sw1",
		Vendor:   "cisco-ios",
		Interfaces: []ir.Interface{
			{Name: "Vlan10", IPv4: "10.0.10.1 255.255.255.0"},
		},
	}}
	svc := NewService(devices, NewFakeRunner(), WithManagementIPs(map[string]string{
		"edge-sw1": "192.168.1.100",
	}))
	target, err := svc.resolveTarget("edge-sw1")
	if err != nil {
		t.Fatal(err)
	}
	if target.Address != "192.168.1.100" {
		t.Fatalf("address = %q, want 192.168.1.100", target.Address)
	}
	if target.Vendor != "cisco-ios" {
		t.Fatalf("vendor = %q, want cisco-ios", target.Vendor)
	}

	fallback := NewService(devices, NewFakeRunner())
	target, err = fallback.resolveTarget("edge-sw1")
	if err != nil {
		t.Fatal(err)
	}
	if target.Address != "10.0.10.1" {
		t.Fatalf("fallback address = %q, want 10.0.10.1", target.Address)
	}
}

func TestObservedVerdictHelpers(t *testing.T) {
	if observedFromPing(&ParsedPing{Received: 5, LossPct: 0}) != ObservedReachable {
		t.Fatal("expected reachable")
	}
	if observedFromPing(&ParsedPing{Received: 0, LossPct: 100}) != ObservedUnreachable {
		t.Fatal("expected unreachable")
	}
	if computeAgreement(pathtrace.VerdictDelivered, VerdictReachable) != AgreementMatch {
		t.Fatal("expected match")
	}
	if computeAgreement(pathtrace.VerdictDelivered, VerdictUnreachable) != AgreementMismatch {
		t.Fatal("expected mismatch")
	}
}

func TestFakeRunnerMissingScript(t *testing.T) {
	runner := NewFakeRunner()
	_, err := runner.Run(context.Background(), Target{Host: "x"}, RenderedCommand{Shell: "cmd"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditLogAppend(t *testing.T) {
	var log AuditLog
	id := log.Append(AuditEntry{Target: "sw1", Command: "ping", Status: StatusOK})
	if id == "" || len(log.Entries()) != 1 {
		t.Fatalf("audit = %#v", log.Entries())
	}
}

func pingDevices() []ir.Device {
	return []ir.Device{{
		Hostname: "edge-sw1",
		Vendor:   "cisco-ios",
		Interfaces: []ir.Interface{
			{Name: "Vlan10", IPv4: "10.0.10.1 255.255.255.0"},
		},
	}}
}

func execDevices() []ir.Device {
	return []ir.Device{{
		Hostname: "edge-fw1",
		Vendor:   "pan-os",
		Interfaces: []ir.Interface{
			{Name: "ethernet1/2", IPv4: "10.0.10.1/24"},
		},
	}}
}

func validatePathDevices() []ir.Device {
	ev := ir.Evidence{File: "test", StartLine: 1, EndLine: 1, RawBlock: "test", Parser: "test"}
	return []ir.Device{
		{
			Hostname: "edge-sw1",
			Vendor:   "cisco-ios",
			Evidence: ev,
			Interfaces: []ir.Interface{
				{Name: "GigabitEthernet1/0/1", IPv4: "10.0.10.1 255.255.255.0", Evidence: ev},
				{Name: "GigabitEthernet1/0/24", IPv4: "10.0.99.2 255.255.255.252", Evidence: ev},
			},
			Routes: []ir.Route{
				{Destination: "0.0.0.0 0.0.0.0", NextHop: "10.0.99.1", Evidence: ev},
			},
		},
		{
			Hostname: "core-rtr1",
			Vendor:   "juniper",
			Evidence: ev,
			Interfaces: []ir.Interface{
				{Name: "ge-0/0/0", IPv4: "10.0.99.1/30", Evidence: ev},
				{Name: "ge-0/0/3", IPv4: "10.0.99.253/30", Evidence: ev},
			},
			Routes: []ir.Route{
				{Destination: "192.168.50.0/24", NextHop: "10.0.99.254", Evidence: ev},
			},
		},
		{
			Hostname: "edge-fw1",
			Vendor:   "pan-os",
			Evidence: ev,
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

func scriptReachable(runner *FakeRunner) {
	ok := RawResult{
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

func TestDiagnoseTargetNotFound(t *testing.T) {
	svc := NewService(nil, NewFakeRunner())
	_, err := svc.Diagnose(context.Background(), DiagRequest{Target: "missing", Command: "ping", Args: DiagArgs{Dst: "1.1.1.1"}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDiagnoseNoRunner(t *testing.T) {
	svc := NewService(pingDevices(), nil)
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target: "edge-sw1", Command: "ping", Args: DiagArgs{Dst: "10.0.99.1"},
	})
	if err == nil || res.Status != StatusError {
		t.Fatalf("res=%#v err=%v", res, err)
	}
}

func TestRenderShowJuniper(t *testing.T) {
	got := renderShow("juniper", "show route")
	if got != "display route" {
		t.Fatalf("got %q", got)
	}
}

func TestStatusFromRunUnreachable(t *testing.T) {
	if statusFromRun(context.Background(), nil, RawResult{ExitCode: 1}, "ping") != StatusUnreachable {
		t.Fatal("expected unreachable")
	}
	if statusFromRun(context.Background(), errors.New("host unreachable"), RawResult{}, "exec") != StatusUnreachable {
		t.Fatal("expected unreachable from error")
	}
}

func TestRenderTracerouteAndShow(t *testing.T) {
	if got := renderTraceroute("juniper", "10.0.0.1", ""); got != "traceroute 10.0.0.1" {
		t.Fatalf("got %q", got)
	}
	if got := renderTraceroute("mikrotik-routeros", "10.0.0.1", ""); got != "/tool traceroute 10.0.0.1" {
		t.Fatalf("got %q", got)
	}
	if got := renderShow("cisco-ios", "display ip route"); got != "show ip route" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderCommandErrors(t *testing.T) {
	if _, err := renderCommand("cisco-ios", "ping", DiagArgs{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := renderCommand("cisco-ios", "show", DiagArgs{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := renderCommand("cisco-ios", "nope", DiagArgs{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseLinuxPingOutput(t *testing.T) {
	out := "5 packets transmitted, 5 received, 0% packet loss, time 4005ms\nrtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms"
	p := parseLinuxPing(out)
	if p == nil || p.Sent != 5 || p.LossPct != 0 || p.RTTAvgMs != 0.2 {
		t.Fatalf("parsed = %#v", p)
	}
}

func TestClassifyDiagnosticRaw(t *testing.T) {
	if !isDiagnosticRaw("show ip route") {
		t.Fatal("expected diagnostic raw")
	}
	if classifyCommand("show", "display route") != ClassDiagnostic {
		t.Fatal("expected diagnostic")
	}
}

func TestConfigWriteCapability(t *testing.T) {
	runner := NewFakeRunner()
	runner.Set("edge-sw1", "configure terminal", RawResult{Output: "entering config mode", ExitCode: 0})
	svc := NewService(pingDevices(), runner, WithConfigWriteCap(true),
		WithApprovals(NewStaticApprovals(ApprovalRecord{Token: "cfg", Target: "edge-sw1"})))
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:        "edge-sw1",
		Command:       "exec",
		Args:          DiagArgs{Raw: "configure terminal"},
		ApprovalToken: "cfg",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusOK || res.Class != ClassConfig {
		t.Fatalf("result = %#v", res)
	}
}

func TestObservedVerdictPartialAndInconclusive(t *testing.T) {
	checks := []ValidationCheck{
		{Observed: ObservedReachable},
		{Observed: ObservedInconclusive},
	}
	if got := observedVerdict(checks); got != VerdictInconclusive {
		t.Fatalf("got %q", got)
	}
	if observedFromPing(nil) != ObservedInconclusive {
		t.Fatal("expected inconclusive")
	}
}

func TestValidatePathNoHops(t *testing.T) {
	devices := []ir.Device{{
		Hostname: "iso",
		Vendor:   "cisco-ios",
		Interfaces: []ir.Interface{
			{Name: "Lo0", IPv4: "1.1.1.1/32"},
		},
	}}
	svc := NewService(devices, NewFakeRunner())
	out, err := svc.ValidatePath(context.Background(), pathtrace.Flow{
		Src: "9.9.9.9", Dst: "8.8.8.8", Proto: "icmp",
	}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if out.ObservedVerdict != VerdictInconclusive {
		t.Fatalf("verdict = %q", out.ObservedVerdict)
	}
}

func TestFakeRunnerDefaultScript(t *testing.T) {
	runner := NewFakeRunner()
	runner.SetDefault("edge-sw1", RawResult{Output: "ok", ExitCode: 0})
	res, err := runner.Run(context.Background(), Target{Host: "edge-sw1"}, RenderedCommand{Shell: "any"})
	if err != nil || res.Output != "ok" {
		t.Fatalf("res=%#v err=%v", res, err)
	}
}

func TestDiagnoseTraceroute(t *testing.T) {
	runner := NewFakeRunner()
	runner.Set("edge-sw1", "traceroute 192.168.50.20", RawResult{
		Output:   " 1  10.0.99.1  1 ms\n 2  192.168.50.20  2 ms\n",
		ExitCode: 0,
	})
	svc := NewService(pingDevices(), runner)
	res, err := svc.Diagnose(context.Background(), DiagRequest{
		Target:  "edge-sw1",
		Command: "traceroute",
		Args:    DiagArgs{Dst: "192.168.50.20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Parsed == nil || res.Parsed.Traceroute == nil || len(res.Parsed.Traceroute.Hops) != 2 {
		t.Fatalf("parsed = %#v", res.Parsed)
	}
}

func TestStatusTimeout(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if statusFromRun(ctx, context.DeadlineExceeded, RawResult{}, "ping") != StatusTimeout {
		t.Fatal("expected timeout")
	}
}

func TestNormalizeVendorCiscoAlias(t *testing.T) {
	if normalizeVendor("cisco") != "cisco-ios" {
		t.Fatal("expected cisco-ios")
	}
}

func TestComputeAgreementDroppedMatch(t *testing.T) {
	if computeAgreement(pathtrace.VerdictDroppedACL, VerdictUnreachable) != AgreementMatch {
		t.Fatal("expected match for dropped + unreachable")
	}
}
