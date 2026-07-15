package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"network-compiler/internal/diag"
	"network-compiler/internal/guard"
)

func TestRunRejectsUnverifiedPlan(t *testing.T) {
	_, err := Run(context.Background(), guard.Plan{}, Options{OutDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "plan hash not verified") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunRejectsMissingOutDir(t *testing.T) {
	_, err := Run(context.Background(), guard.Plan{}, Options{PlanVerified: true})
	if err == nil || !strings.Contains(err.Error(), "out dir") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunSimulateWritesDiscoveryLayout(t *testing.T) {
	plan := allowedPlan(t)
	out := filepath.Join(t.TempDir(), "collect-out")
	audit := filepath.Join(t.TempDir(), "audit.jsonl")
	result, err := Run(context.Background(), plan, Options{
		OutDir:       out,
		Simulate:     true,
		PlanVerified: true,
		User:         "admin",
		AuditLog:     audit,
		Timeout:      5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Commands != 2 || result.Errors != 0 {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Targets) != 1 || result.Targets[0].Device != "sw1" {
		t.Fatalf("targets = %#v", result.Targets)
	}

	mdPath := filepath.Join(out, "sw1", "metadata.json")
	mdData, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	var md deviceMetadata
	if err := json.Unmarshal(mdData, &md); err != nil {
		t.Fatal(err)
	}
	if md.Hostname != "sw1" || md.Vendor != "cisco-ios" || md.Source != "collect" {
		t.Fatalf("metadata = %#v", md)
	}

	lldp, err := os.ReadFile(filepath.Join(out, "sw1", "show-lldp-neighbors-detail.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lldp), "System Name: sw2") {
		t.Fatalf("lldp = %q", lldp)
	}

	arp, err := os.ReadFile(filepath.Join(out, "sw1", "show-arp.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arp), "10.0.10.21") {
		t.Fatalf("arp = %q", arp)
	}

	auditData, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(auditData)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d", len(lines))
	}
}

func TestRunSimulateSkipsRejectedTargets(t *testing.T) {
	cfg, err := guard.ReadConfig(filepath.Join("..", "..", "testdata", "guard", "guard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := guard.ReadTargets(filepath.Join("..", "..", "testdata", "guard", "targets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := guard.BuildPlan(cfg, targets)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	result, err := Run(context.Background(), plan, Options{
		OutDir:       out,
		Simulate:     true,
		PlanVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("targets = %d, want 1 allowed", len(result.Targets))
	}
	if _, err := os.Stat(filepath.Join(out, "sw2")); !os.IsNotExist(err) {
		t.Fatal("sw2 should not be collected")
	}
}

func TestRunRedactsSecretsInOutput(t *testing.T) {
	plan := guard.Plan{
		Targets: []guard.Decision{{
			Allowed: true,
			Target: guard.Target{
				Device:       "sw1",
				ManagementIP: "10.0.1.10",
				Commands:     []string{"show running-config"},
			},
			Commands: []guard.CommandDecision{{Command: "show running-config", Allowed: true}},
		}},
	}
	out := t.TempDir()
	_, err := Run(context.Background(), plan, Options{
		OutDir:       out,
		Simulate:     true,
		PlanVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "sw1", "show-running-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "$1$abc$def") {
		t.Fatalf("secret not redacted: %q", text)
	}
	if !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("expected redaction marker: %q", text)
	}
}

func TestRunWithInjectedRunnerRecordsErrors(t *testing.T) {
	runner := diag.NewFakeRunner()
	runner.Set("sw1", "show arp", diag.RawResult{ExitCode: 1, Err: diagErr("boom")})
	plan := guard.Plan{
		Targets: []guard.Decision{{
			Allowed: true,
			Target: guard.Target{
				Device:       "sw1",
				ManagementIP: "10.0.1.10",
				Commands:     []string{"show arp"},
			},
			Commands: []guard.CommandDecision{{Command: "show arp", Allowed: true}},
		}},
	}
	out := t.TempDir()
	result, err := Run(context.Background(), plan, Options{
		OutDir:       out,
		PlanVerified: true,
		Runner:       runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Errors != 1 {
		t.Fatalf("errors = %d", result.Errors)
	}
	if result.Targets[0].Commands[0].Status != "error" {
		t.Fatalf("command = %#v", result.Targets[0].Commands[0])
	}
}

func TestCommandOutputName(t *testing.T) {
	got := commandOutputName("show lldp neighbors detail")
	if got != "show-lldp-neighbors-detail.txt" {
		t.Fatalf("name = %q", got)
	}
}

func TestFilenameToCommand(t *testing.T) {
	cmd, ok := filenameToCommand("show-arp.txt")
	if !ok || cmd != "show arp" {
		t.Fatalf("command = %q ok=%v", cmd, ok)
	}
	cmd, ok = filenameToCommand("show-running-config.txt")
	if !ok || cmd != "show running-config" {
		t.Fatalf("running-config = %q ok=%v", cmd, ok)
	}
	cmd, ok = filenameToCommand("show-vlan.txt")
	if !ok || cmd != "show vlan" {
		t.Fatalf("fallback = %q ok=%v", cmd, ok)
	}
	if _, ok := filenameToCommand("bad"); ok {
		t.Fatal("expected unknown filename")
	}
	cmd, ok = filenameToCommand("show-version.txt")
	if !ok || cmd != "show version" {
		t.Fatalf("custom = %q ok=%v", cmd, ok)
	}
}

func TestCommandOutputNameFallback(t *testing.T) {
	got := commandOutputName("show version")
	if got != "show-version.txt" {
		t.Fatalf("name = %q", got)
	}
}

func TestSelectRunnerModes(t *testing.T) {
	injected := diag.NewFakeRunner()
	r, err := selectRunner(Options{Runner: injected})
	if err != nil || r != injected {
		t.Fatalf("injected runner = %#v err=%v", r, err)
	}
	r, err = selectRunner(Options{Simulate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*diag.FakeRunner); !ok {
		t.Fatalf("simulate runner type = %T", r)
	}
	r, err = selectRunner(Options{UseExecRunner: true})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("exec runner is nil")
	}
	r, err = selectRunner(Options{KnownHosts: t.TempDir() + "/known_hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("ssh runner is nil")
	}
}

func TestRunRejectsMissingDevice(t *testing.T) {
	plan := guard.Plan{
		Targets: []guard.Decision{{
			Allowed:  true,
			Target:   guard.Target{ManagementIP: "10.0.1.10"},
			Commands: []guard.CommandDecision{{Command: "show arp", Allowed: true}},
		}},
	}
	result, err := Run(context.Background(), plan, Options{
		OutDir:       t.TempDir(),
		Simulate:     true,
		PlanVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Errors != 1 || result.Targets[0].Error == "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestOpenAuditCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	aw, err := openAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	aw.append(collectAuditEntry{Device: "sw1", Command: "show arp", Status: "ok"})
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"device":"sw1"`) {
		t.Fatalf("audit = %q", data)
	}
}

func TestAllowedTargetsSorted(t *testing.T) {
	plan := guard.Plan{Targets: []guard.Decision{
		{Allowed: true, Target: guard.Target{Device: "sw2", ManagementIP: "10.0.2.10"}},
		{Allowed: false, Target: guard.Target{Device: "sw9", ManagementIP: "10.0.9.10"}},
		{Allowed: true, Target: guard.Target{Device: "sw1", ManagementIP: "10.0.1.10"}},
	}}
	got := allowedTargets(plan)
	if len(got) != 2 || got[0].Target.Device != "sw1" || got[1].Target.Device != "sw2" {
		t.Fatalf("targets = %#v", got)
	}
}

func TestRedactOutput(t *testing.T) {
	got := redactOutput("username admin secret 5 $1$abc$def\n")
	if strings.Contains(got, "$1$abc") {
		t.Fatalf("not redacted: %q", got)
	}
}

func TestSimulateRunnerLoadsEmbeddedScripts(t *testing.T) {
	runner, err := newSimulateRunner()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := runner.Run(context.Background(), diag.Target{Host: "sw1"}, diag.RenderedCommand{
		Shell: "show arp",
		Kind:  "show",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw.Output, "10.0.10.21") {
		t.Fatalf("output = %q", raw.Output)
	}
}

func allowedPlan(t *testing.T) guard.Plan {
	t.Helper()
	return guard.Plan{
		GuardVersion: "lab-guard-v1",
		Targets: []guard.Decision{{
			Allowed: true,
			Target: guard.Target{
				Device:       "sw1",
				ManagementIP: "10.0.1.10",
				Source:       "inventory",
				Commands:     []string{"show lldp neighbors detail", "show arp"},
			},
			Commands: []guard.CommandDecision{
				{Command: "show lldp neighbors detail", Allowed: true},
				{Command: "show arp", Allowed: true},
			},
		}},
	}
}

type diagErr string

func (e diagErr) Error() string { return string(e) }

func TestRunLivePassesCredsToRunner(t *testing.T) {
	runner := diag.NewFakeRunner()
	runner.Set("sw1", "show arp", diag.RawResult{Output: "Protocol  Address\n", ExitCode: 0})
	plan := guard.Plan{
		Targets: []guard.Decision{{
			Allowed: true,
			Target: guard.Target{
				Device:       "sw1",
				ManagementIP: "10.0.1.10",
				Commands:     []string{"show arp"},
			},
			Commands: []guard.CommandDecision{{Command: "show arp", Allowed: true}},
		}},
	}
	creds := diag.CredRef{Username: "netops", Secret: "secret", KeyFile: "/keys/lab"}
	out := t.TempDir()
	result, err := Run(context.Background(), plan, Options{
		OutDir:       out,
		PlanVerified: true,
		Runner:       runner,
		Creds:        creds,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.Calls) != 1 {
		t.Fatalf("calls = %d", len(runner.Calls))
	}
	got := runner.Calls[0].Target.Creds
	if got.Username != "netops" || got.Secret != "secret" || got.KeyFile != "/keys/lab" {
		t.Fatalf("creds = %#v", got)
	}
	if runner.Calls[0].Target.Address != "10.0.1.10" {
		t.Fatalf("address = %q", runner.Calls[0].Target.Address)
	}
	if result.Errors != 0 || result.Targets[0].Commands[0].Status != "ok" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(out, "sw1", "show-arp.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestMergeCredsUsesUserFallback(t *testing.T) {
	got := mergeCreds("admin", diag.CredRef{Secret: "pw"})
	if got.Username != "admin" || got.Secret != "pw" {
		t.Fatalf("creds = %#v", got)
	}
}

func TestConfigPathsFindsRunningConfigs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sw1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sw2"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sw1", "show-running-config.txt"), []byte("hostname sw1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sw2", "show-running-config.txt"), []byte("hostname sw2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	paths, err := ConfigPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("paths = %#v", paths)
	}
	if paths[0] >= paths[1] {
		t.Fatalf("paths not sorted: %#v", paths)
	}
}

func TestRunLiveSelectsSSHRunner(t *testing.T) {
	runner, err := selectRunner(Options{KnownHosts: t.TempDir() + "/known_hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if runner == nil {
		t.Fatal("runner is nil")
	}
}

func TestConfigPathsMissingConfigs(t *testing.T) {
	_, err := ConfigPaths(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no show-running-config.txt") {
		t.Fatalf("err = %v", err)
	}
}
