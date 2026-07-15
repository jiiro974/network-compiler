package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildPlanAppliesScopeCommandsAndNeighborPolicy(t *testing.T) {
	cfg, err := ReadConfig(filepath.Join("..", "..", "testdata", "guard", "guard.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := ReadTargets(filepath.Join("..", "..", "testdata", "guard", "targets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(cfg, targets)
	if err != nil {
		t.Fatal(err)
	}
	if plan.GuardVersion != "lab-guard-v1" || plan.SHA256 == "" {
		t.Fatalf("bad plan identity: %#v", plan)
	}
	if plan.Summary.TargetsInput != 5 || plan.Summary.Allowed != 1 || plan.Summary.Rejected != 4 {
		t.Fatalf("summary = %#v", plan.Summary)
	}
	byDevice := map[string]Decision{}
	for _, decision := range plan.Targets {
		byDevice[decision.Target.Device] = decision
	}
	if !byDevice["sw1"].Allowed || byDevice["sw1"].MatchedAllowCIDR != "10.0.0.0/8" {
		t.Fatalf("sw1 decision = %#v", byDevice["sw1"])
	}
	if byDevice["sw2"].Allowed || !hasReason(byDevice["sw2"], "command rejected: configure terminal") {
		t.Fatalf("sw2 decision = %#v", byDevice["sw2"])
	}
	if byDevice["sw-denied"].Allowed || byDevice["sw-denied"].MatchedDenyCIDR != "10.0.9.0/24" {
		t.Fatalf("sw-denied decision = %#v", byDevice["sw-denied"])
	}
	if byDevice["internet"].Allowed || !hasReason(byDevice["internet"], "no allow_cidr match") {
		t.Fatalf("internet decision = %#v", byDevice["internet"])
	}
	if byDevice["sw-neighbor"].Allowed || !hasReason(byDevice["sw-neighbor"], "neighbor targets require human promotion") {
		t.Fatalf("neighbor decision = %#v", byDevice["sw-neighbor"])
	}
}

func TestPlanHashIsStableAndVerifiable(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowCIDRs = []string{"10.0.0.0/8"}
	targets := []Target{{Device: "sw1", ManagementIP: "10.0.0.1", Source: "inventory"}}
	first, err := BuildPlan(cfg, targets)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(cfg, targets)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != second.SHA256 {
		t.Fatalf("hash not stable: %s != %s", first.SHA256, second.SHA256)
	}
	if err := VerifyPlanHash(first, first.SHA256); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPlanHash(first, "bad"); err == nil {
		t.Fatal("expected hash mismatch")
	}
}

func TestWriteAudit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowCIDRs = []string{"10.0.0.0/8"}
	targets := []Target{
		{Device: "sw1", ManagementIP: "10.0.0.1", Source: "inventory"},
		{Device: "wan", ManagementIP: "203.0.113.10", Source: "inventory"},
	}
	plan, err := BuildPlan(cfg, targets)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg.Audit.LogFile = path
	if err := WriteAudit(path, plan, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitNonEmptyLines(string(data))
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want 2", len(lines))
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatal(err)
	}
	if row["guard"] != DefaultVersion {
		t.Fatalf("audit guard = %#v", row)
	}
}

func hasReason(decision Decision, reason string) bool {
	for _, got := range decision.Reasons {
		if got == reason {
			return true
		}
	}
	return false
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
